use std::collections::HashMap;

use api_models::payments::QrCodeInformation;
use common_enums::enums;
use common_utils::types::StringMinorUnit;
use common_utils::{ext_traits::Encode, request::Method};
use error_stack::ResultExt;
use hyperswitch_domain_models::{
    payment_method_data::{BankTransferData, Card, PaymentMethodData, VoucherData},
    router_data::{ConnectorAuthType, ErrorResponse, PaymentMethodToken, RouterData},
    router_flow_types::refunds::{Execute, RSync},
    router_request_types::ResponseId,
    router_response_types::{PaymentsResponseData, RedirectForm, RefundsResponseData},
    types::{PaymentsAuthorizeRouterData, RefundsRouterData, TokenizationRouterData},
};
use hyperswitch_interfaces::errors;
use hyperswitch_masking::{PeekInterface, Secret};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    types::{RefundsResponseRouterData, ResponseRouterData},
    utils::{CardData, PaymentsAuthorizeRequestData, QrImage, RouterData as _},
};

pub struct IuguRouterData<T> {
    pub amount: i64,
    pub router_data: T,
}

impl<T> IuguRouterData<T> {
    pub fn from_minor(
        amount: StringMinorUnit,
        router_data: T,
    ) -> Result<Self, error_stack::Report<errors::ConnectorError>> {
        let parsed = amount
            .to_string()
            .parse::<i64>()
            .map_err(|_| errors::ConnectorError::RequestEncodingFailed)?;
        Ok(Self {
            amount: parsed,
            router_data,
        })
    }
}

pub struct IuguAuthType {
    pub(super) api_key: Secret<String>,
    pub(super) account_id: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for IuguAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::BodyKey { api_key, key1 } => Ok(Self {
                api_key: api_key.to_owned(),
                account_id: key1.to_owned(),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

/// IUGU `months` is omitted for à vista and accepts 2 through 12.
pub fn months_for_iugu(
    installments: Option<u8>,
) -> Result<Option<u8>, error_stack::Report<errors::ConnectorError>> {
    match installments {
        None | Some(0) | Some(1) => Ok(None),
        Some(months) if (2..=12).contains(&months) => Ok(Some(months)),
        Some(months) => Err(errors::ConnectorError::NotSupported {
            message: format!("IUGU parcelamento aceita months de 2 a 12, recebido {months}"),
            connector: "iugu",
        }
        .into()),
    }
}

pub fn basic_auth_header(api_token: &str) -> String {
    let encoded = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        format!("{api_token}:"),
    );
    format!("Basic {encoded}")
}

#[derive(Debug, Serialize)]
pub struct IuguTokenRequest {
    account_id: Secret<String>,
    method: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    test: Option<bool>,
    data: IuguTokenCard,
}

#[derive(Debug, Serialize)]
pub struct IuguTokenCard {
    number: Secret<String>,
    verification_value: Secret<String>,
    first_name: Secret<String>,
    last_name: Secret<String>,
    month: Secret<String>,
    year: Secret<String>,
}

impl TryFrom<&TokenizationRouterData> for IuguTokenRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &TokenizationRouterData) -> Result<Self, Self::Error> {
        let auth = IuguAuthType::try_from(&item.connector_auth_type)?;
        let PaymentMethodData::Card(card) = &item.request.payment_method_data else {
            return Err(errors::ConnectorError::NotSupported {
                message: "IUGU tokeniza apenas cartão".to_string(),
                connector: "iugu",
            }
            .into());
        };
        let (first_name, last_name) = split_card_holder(card)?;
        Ok(Self {
            account_id: auth.account_id,
            method: "credit_card",
            test: item.test_mode,
            data: IuguTokenCard {
                number: Secret::new(card.card_number.get_card_no()),
                verification_value: card.card_cvc.clone(),
                first_name,
                last_name,
                month: card.get_card_expiry_month_2_digit()?,
                year: card.get_expiry_year_4_digit(),
            },
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IuguTokenResponse {
    id: String,
}

impl<F, T> TryFrom<ResponseRouterData<F, IuguTokenResponse, T, PaymentsResponseData>>
    for RouterData<F, T, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: ResponseRouterData<F, IuguTokenResponse, T, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(PaymentsResponseData::TokenizationResponse {
                token: item.response.id,
            }),
            ..item.data
        })
    }
}

#[derive(Debug, Serialize)]
pub struct IuguChargeRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    token: Option<Secret<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    customer_payment_method_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    method: Option<&'static str>,
    email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    months: Option<u8>,
    items: Vec<IuguItem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    payer: Option<IuguPayer>,
    order_id: String,
}

#[derive(Debug, Serialize)]
pub struct IuguInvoiceRequest {
    email: String,
    due_date: String,
    items: Vec<IuguItem>,
    payable_with: Vec<&'static str>,
    payer: IuguPayer,
    order_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct IuguItem {
    description: String,
    quantity: i64,
    price_cents: i64,
}

#[derive(Debug, Serialize)]
pub struct IuguPayer {
    #[serde(skip_serializing_if = "Option::is_none")]
    cpf_cnpj: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    phone_prefix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    phone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<IuguAddress>,
}

#[derive(Debug, Serialize)]
pub struct IuguAddress {
    #[serde(skip_serializing_if = "Option::is_none")]
    street: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    city: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    zip_code: Option<String>,
}

pub enum IuguAuthorizeRequest {
    Charge(IuguChargeRequest),
    Invoice(IuguInvoiceRequest),
}

impl IuguAuthorizeRequest {
    pub fn path(&self) -> &'static str {
        match self {
            Self::Charge(_) => "charge",
            Self::Invoice(_) => "invoices",
        }
    }
}

impl TryFrom<&IuguRouterData<&PaymentsAuthorizeRouterData>> for IuguAuthorizeRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &IuguRouterData<&PaymentsAuthorizeRouterData>) -> Result<Self, Self::Error> {
        let request = &item.router_data.request;
        let months = months_for_iugu(
            request
                .installment_details
                .as_ref()
                .map(|details| details.number_of_installments.get()),
        )?;
        let description = item
            .router_data
            .description
            .clone()
            .unwrap_or_else(|| "Pagamento".to_string());
        let items = vec![IuguItem {
            description,
            quantity: 1,
            price_cents: item.amount,
        }];
        let order_id = item.router_data.connector_request_reference_id.clone();
        match request.payment_method_data.clone() {
            PaymentMethodData::Card(_) | PaymentMethodData::MandatePayment => {
                let email = request
                    .get_optional_email()
                    .or_else(|| item.router_data.get_optional_billing_email())
                    .ok_or(errors::ConnectorError::MissingRequiredField {
                        field_name: "email",
                    })?;
                let stored = stored_card_reference(item.router_data);
                let (token, customer_payment_method_id) = match stored {
                    Some(StoredCard::Token(token)) => (Some(Secret::new(token)), None),
                    Some(StoredCard::PaymentMethod(id)) => (None, Some(id)),
                    None => {
                        return Err(errors::ConnectorError::NotImplemented(
                            "IUGU cobra cartão com token de POST /v1/payment_token ou customer_payment_method_id"
                                .to_string(),
                        )
                        .into());
                    }
                };
                Ok(Self::Charge(IuguChargeRequest {
                    token,
                    customer_payment_method_id,
                    method: None,
                    email: email.peek().to_string(),
                    months,
                    items: items.clone(),
                    payer: Some(payer_from_router(item.router_data)),
                    order_id,
                }))
            }
            PaymentMethodData::Voucher(VoucherData::Boleto(_)) => {
                let email = require_email(item.router_data)?;
                Ok(Self::Charge(IuguChargeRequest {
                    token: None,
                    customer_payment_method_id: None,
                    method: Some("bank_slip"),
                    email,
                    months: None,
                    items: items.clone(),
                    payer: Some(payer_from_router(item.router_data)),
                    order_id,
                }))
            }
            PaymentMethodData::BankTransfer(transfer) if is_pix(transfer.as_ref()) => {
                Ok(Self::Invoice(IuguInvoiceRequest {
                    email: require_email(item.router_data)?,
                    due_date: today(),
                    items: items.clone(),
                    payable_with: vec!["pix"],
                    payer: payer_from_router(item.router_data),
                    order_id,
                }))
            }
            PaymentMethodData::CardRedirect(_)
            | PaymentMethodData::Wallet(_)
            | PaymentMethodData::PayLater(_)
            | PaymentMethodData::BankRedirect(_)
            | PaymentMethodData::BankDebit(_)
            | PaymentMethodData::BankTransfer(_)
            | PaymentMethodData::Crypto(_)
            | PaymentMethodData::Reward
            | PaymentMethodData::RealTimePayment(_)
            | PaymentMethodData::Upi(_)
            | PaymentMethodData::Voucher(_)
            | PaymentMethodData::GiftCard(_)
            | PaymentMethodData::CardToken(_)
            | PaymentMethodData::OpenBanking(_)
            | PaymentMethodData::NetworkToken(_)
            | PaymentMethodData::MobilePayment(_)
            | PaymentMethodData::CardWithOptionalCVC(_)
            | PaymentMethodData::CardWithNetworkTokenDetails(_)
            | PaymentMethodData::CardDetailsForNetworkTransactionId(_)
            | PaymentMethodData::CardWithLimitedDetails(_)
            | PaymentMethodData::NetworkTokenDetailsForNetworkTransactionId(_)
            | PaymentMethodData::DecryptedWalletTokenDetailsForNetworkTransactionId(_) => {
                Err(errors::ConnectorError::NotSupported {
                    message: "forma de pagamento não suportada pela IUGU".to_string(),
                    connector: "iugu",
                }
                .into())
            }
        }
    }
}

fn is_pix(data: &BankTransferData) -> bool {
    matches!(
        data,
        BankTransferData::Pix { .. } | BankTransferData::PixQr {} | BankTransferData::PixEmv {}
    )
}

enum StoredCard {
    Token(String),
    PaymentMethod(String),
}

fn stored_card_reference(item: &PaymentsAuthorizeRouterData) -> Option<StoredCard> {
    if let Some(PaymentMethodToken::Token(token)) = &item.payment_method_token {
        return Some(StoredCard::Token(token.peek().to_string()));
    }
    item.request
        .connector_mandate_id()
        .map(StoredCard::PaymentMethod)
}

fn require_email(item: &PaymentsAuthorizeRouterData) -> Result<String, errors::ConnectorError> {
    item.request
        .get_optional_email()
        .or_else(|| item.get_optional_billing_email())
        .map(|email| email.peek().to_string())
        .ok_or(errors::ConnectorError::MissingRequiredField {
            field_name: "email",
        })
}

fn payer_from_router(item: &PaymentsAuthorizeRouterData) -> IuguPayer {
    let name = item
        .request
        .customer_name
        .as_ref()
        .map(|value| value.peek().to_string())
        .or_else(|| {
            item.get_optional_billing_full_name()
                .map(|value| value.peek().to_string())
        });
    let cpf_cnpj = document_from_payment_method(&item.request.payment_method_data)
        .or_else(|| metadata_digits(item.request.metadata.as_ref()));
    let (phone_prefix, phone) = item
        .get_optional_billing_phone_number()
        .map(|value| split_phone(value.peek()))
        .unwrap_or((None, None));
    IuguPayer {
        cpf_cnpj,
        name,
        email: item
            .request
            .get_optional_email()
            .map(|email| email.peek().to_string()),
        phone_prefix,
        phone,
        address: Some(IuguAddress {
            street: item
                .get_optional_billing_line1()
                .map(|value| value.peek().to_string()),
            number: item
                .get_optional_billing_line2()
                .map(|value| value.peek().to_string()),
            city: item.get_optional_billing_city(),
            state: item
                .get_optional_billing_state()
                .map(|value| value.peek().to_string()),
            zip_code: item
                .get_optional_billing_zip()
                .map(|value| digits_only(value.peek())),
        }),
    }
}

fn metadata_digits(metadata: Option<&serde_json::Value>) -> Option<String> {
    let metadata = metadata?;
    ["cpfCnpj", "cpf_cnpj", "cpf", "cnpj"]
        .iter()
        .find_map(|key| {
            metadata
                .get(*key)
                .and_then(|value| value.as_str())
                .map(digits_only)
                .filter(|value| !value.is_empty())
        })
}

fn document_from_payment_method(data: &PaymentMethodData) -> Option<String> {
    match data {
        PaymentMethodData::BankTransfer(transfer) => match transfer.as_ref() {
            BankTransferData::Pix { cpf, cnpj, .. } => cpf
                .clone()
                .or(cnpj.clone())
                .map(|value| digits_only(value.peek())),
            _ => None,
        },
        PaymentMethodData::Voucher(VoucherData::Boleto(boleto)) => boleto
            .social_security_number
            .as_ref()
            .map(|value| digits_only(value.peek())),
        _ => None,
    }
}

fn split_card_holder(
    card: &Card,
) -> Result<(Secret<String>, Secret<String>), error_stack::Report<errors::ConnectorError>> {
    let name = card.get_cardholder_name()?.peek().to_string();
    let (first, last) = split_name(&name);
    Ok((Secret::new(first), Secret::new(last)))
}

fn split_name(name: &str) -> (String, String) {
    match name.split_once(' ') {
        Some((first, last)) if !last.is_empty() => (first.to_string(), last.to_string()),
        _ => (name.to_string(), "-".to_string()),
    }
}

fn digits_only(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_digit())
        .collect()
}

fn split_phone(phone: &str) -> (Option<String>, Option<String>) {
    let digits = digits_only(phone);
    let local = if digits.starts_with("55") && digits.len() > 11 {
        digits.chars().skip(2).collect::<String>()
    } else {
        digits
    };
    if local.len() < 3 {
        return (None, None);
    }
    let prefix: String = local.chars().take(2).collect();
    let number: String = local.chars().skip(2).collect();
    (Some(prefix), Some(number))
}

fn today() -> String {
    time::OffsetDateTime::now_utc().date().to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IuguPaymentsResponse {
    #[serde(default)]
    success: Option<bool>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default, rename = "LR")]
    lr: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    invoice_id: Option<String>,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    identification: Option<String>,
    #[serde(default)]
    bank_slip_url: Option<String>,
    #[serde(default)]
    errors: Option<serde_json::Value>,
    #[serde(default)]
    pix: Option<IuguPix>,
    #[serde(default)]
    bank_slip: Option<IuguBankSlip>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IuguPix {
    #[serde(default)]
    qrcode: Option<String>,
    #[serde(default)]
    qrcode_text: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IuguBankSlip {
    #[serde(default)]
    digitable_line: Option<String>,
    #[serde(default)]
    barcode_data: Option<String>,
    #[serde(default)]
    bank_slip_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayErrorParts {
    pub code: String,
    pub message: String,
    pub reason: Option<String>,
}

pub fn gateway_error_from_iugu(
    lr: Option<String>,
    message: Option<String>,
    errors: Option<serde_json::Value>,
) -> GatewayErrorParts {
    let formatted = errors.as_ref().map(format_iugu_errors);
    if let Some(code) = lr.filter(|value| !value.is_empty()) {
        return GatewayErrorParts {
            code,
            message: message
                .filter(|value| !value.is_empty())
                .or(formatted)
                .unwrap_or_else(|| "recusa da IUGU".to_string()),
            reason: errors.map(|value| value.to_string()),
        };
    }
    if formatted.is_none() {
        if let Some(text) = message.clone().filter(|value| !value.is_empty()) {
            return GatewayErrorParts {
                code: "iugu_error".to_string(),
                message: text,
                reason: None,
            };
        }
    }
    if let Some(errors) = errors {
        let (code, message) = match &errors {
            serde_json::Value::String(value) => ("iugu_error".to_string(), value.clone()),
            serde_json::Value::Object(map) => {
                let code = map
                    .keys()
                    .next()
                    .cloned()
                    .unwrap_or_else(|| "iugu_error".to_string());
                (code, format_iugu_errors(&errors))
            }
            _ => ("iugu_error".to_string(), format_iugu_errors(&errors)),
        };
        return GatewayErrorParts {
            code,
            message,
            reason: Some(errors.to_string()),
        };
    }
    GatewayErrorParts {
        code: "iugu_error".to_string(),
        message: message.unwrap_or_else(|| "recusa da IUGU".to_string()),
        reason: None,
    }
}

fn format_iugu_errors(errors: &serde_json::Value) -> String {
    match errors {
        serde_json::Value::String(value) => value.clone(),
        serde_json::Value::Object(map) => map
            .iter()
            .map(|(key, value)| format!("{key}: {value}"))
            .collect::<Vec<_>>()
            .join("; "),
        other => other.to_string(),
    }
}

pub fn iugu_attempt_status(status: Option<&str>, success: Option<bool>) -> enums::AttemptStatus {
    if success == Some(false) {
        return enums::AttemptStatus::Failure;
    }
    match status.unwrap_or("pending") {
        "captured" | "paid" => enums::AttemptStatus::Charged,
        "authorized" => enums::AttemptStatus::Authorized,
        "partially_paid" => enums::AttemptStatus::PartialCharged,
        "refunded" => enums::AttemptStatus::AutoRefunded,
        "pending" | "in_analysis" => enums::AttemptStatus::AuthenticationPending,
        "canceled" | "cancelled" | "expired" | "unauthorized" | "chargeback" | "in_protest" => {
            enums::AttemptStatus::Failure
        }
        _ => enums::AttemptStatus::Pending,
    }
}

impl IuguPaymentsResponse {
    fn transaction_id(&self) -> Result<String, errors::ConnectorError> {
        self.invoice_id.clone().or(self.id.clone()).ok_or(
            errors::ConnectorError::MissingRequiredField {
                field_name: "invoice_id",
            },
        )
    }

    fn decline(&self, status_code: u16) -> Option<ErrorResponse> {
        let declined = self.success == Some(false)
            || matches!(
                self.status.as_deref(),
                Some("unauthorized" | "canceled" | "cancelled" | "expired" | "chargeback")
            );
        if !declined {
            return None;
        }
        let parts =
            gateway_error_from_iugu(self.lr.clone(), self.message.clone(), self.errors.clone());
        Some(ErrorResponse {
            status_code,
            code: parts.code,
            message: parts.message,
            reason: parts.reason,
            attempt_status: Some(enums::AttemptStatus::Failure),
            connector_transaction_id: self.invoice_id.clone().or(self.id.clone()),
            connector_response_reference_id: None,
            network_advice_code: None,
            network_decline_code: self.lr.clone(),
            network_error_message: self.message.clone(),
            connector_metadata: None,
        })
    }
}

impl<F, T> TryFrom<ResponseRouterData<F, IuguPaymentsResponse, T, PaymentsResponseData>>
    for RouterData<F, T, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: ResponseRouterData<F, IuguPaymentsResponse, T, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        if let Some(error) = item.response.decline(item.http_code) {
            return Ok(Self {
                status: enums::AttemptStatus::Failure,
                response: Err(error),
                ..item.data
            });
        }
        let transaction_id = item.response.transaction_id()?;
        let connector_metadata = payment_metadata(&item.response)?;
        let redirect_url = item
            .response
            .bank_slip
            .as_ref()
            .and_then(|slip| slip.bank_slip_url.clone())
            .or(item.response.bank_slip_url.clone())
            .or(item.response.url.clone());
        Ok(Self {
            status: iugu_attempt_status(item.response.status.as_deref(), item.response.success),
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(transaction_id.clone()),
                redirection_data: Box::new(redirect_form(redirect_url)),
                mandate_reference: Box::new(None),
                connector_metadata,
                network_txn_id: None,
                network_txn_link_id: None,
                connector_response_reference_id: Some(transaction_id),
                incremental_authorization_allowed: None,
                authentication_data: None,
                charges: None,
            }),
            ..item.data
        })
    }
}

fn payment_metadata(
    response: &IuguPaymentsResponse,
) -> Result<Option<serde_json::Value>, error_stack::Report<errors::ConnectorError>> {
    if let Some(text) = response
        .pix
        .as_ref()
        .and_then(|pix| pix.qrcode_text.clone())
    {
        let image = QrImage::new_from_data(text.clone())
            .change_context(errors::ConnectorError::ResponseHandlingFailed)?;
        let image_data_url = Url::parse(image.data.as_str())
            .change_context(errors::ConnectorError::ResponseHandlingFailed)?;
        let qr_code_url = response
            .pix
            .as_ref()
            .and_then(|pix| pix.qrcode.as_ref())
            .and_then(|url| Url::parse(url).ok());
        let info = QrCodeInformation::QrCodeUrl {
            image_data_url,
            qr_code_url,
            display_to_timestamp: None,
            expiry_type: None,
            raw_qr_data: Some(text),
        };
        return info
            .encode_to_value()
            .change_context(errors::ConnectorError::ResponseHandlingFailed)
            .map(Some);
    }
    if let Some(slip) = &response.bank_slip {
        return Ok(Some(serde_json::json!({
            "digitable_line": slip.digitable_line,
            "barcode_data": slip.barcode_data,
            "bank_slip_url": slip.bank_slip_url,
            "identification": response.identification,
        })));
    }
    if response.identification.is_some() {
        return Ok(Some(serde_json::json!({
            "identification": response.identification,
            "bank_slip_url": response.bank_slip_url,
        })));
    }
    Ok(None)
}

fn redirect_form(url: Option<String>) -> Option<RedirectForm> {
    url.map(|endpoint| RedirectForm::Form {
        endpoint,
        method: Method::Get,
        form_fields: HashMap::new(),
    })
}

#[derive(Debug, Serialize)]
pub struct IuguRefundRequest {
    partial_value_refund_cents: i64,
}

impl<F> TryFrom<&IuguRouterData<&RefundsRouterData<F>>> for IuguRefundRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &IuguRouterData<&RefundsRouterData<F>>) -> Result<Self, Self::Error> {
        Ok(Self {
            partial_value_refund_cents: item.amount,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RefundResponse {
    id: String,
    status: String,
}

impl TryFrom<RefundsResponseRouterData<Execute, RefundResponse>> for RefundsRouterData<Execute> {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: RefundsResponseRouterData<Execute, RefundResponse>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.id,
                refund_status: refund_status(&item.response.status),
            }),
            ..item.data
        })
    }
}

impl TryFrom<RefundsResponseRouterData<RSync, RefundResponse>> for RefundsRouterData<RSync> {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: RefundsResponseRouterData<RSync, RefundResponse>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.id,
                refund_status: refund_status(&item.response.status),
            }),
            ..item.data
        })
    }
}

fn refund_status(status: &str) -> enums::RefundStatus {
    match status {
        "refunded" => enums::RefundStatus::Success,
        "canceled" | "cancelled" | "expired" => enums::RefundStatus::Failure,
        _ => enums::RefundStatus::Pending,
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IuguErrorResponse {
    #[serde(default, rename = "LR")]
    pub lr: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub errors: Option<serde_json::Value>,
}

impl IuguErrorResponse {
    pub fn into_parts(self) -> GatewayErrorParts {
        gateway_error_from_iugu(self.lr, self.message, self.errors)
    }
}

#[cfg(test)]
mod tests {
    use super::{gateway_error_from_iugu, iugu_attempt_status, months_for_iugu};

    #[test]
    fn avista_omits_months_and_twelve_is_sent() {
        assert_eq!(months_for_iugu(None).unwrap(), None);
        assert_eq!(months_for_iugu(Some(1)).unwrap(), None);
        assert_eq!(months_for_iugu(Some(12)).unwrap(), Some(12));
        assert!(months_for_iugu(Some(13)).is_err());
    }

    #[test]
    fn decline_keeps_lr_and_gateway_message() {
        let parts = gateway_error_from_iugu(
            Some("51".to_string()),
            Some("Transação negada".to_string()),
            Some(serde_json::json!({})),
        );
        assert_eq!(parts.code, "51");
        assert_eq!(parts.message, "Transação negada");
        assert_eq!(
            iugu_attempt_status(Some("unauthorized"), Some(false)),
            common_enums::AttemptStatus::Failure
        );
    }

    #[test]
    fn validation_error_keeps_field_and_message() {
        let parts = gateway_error_from_iugu(
            None,
            None,
            Some(serde_json::json!({"payer.cpf_cnpj": ["não pode ficar em branco"]})),
        );
        assert_eq!(parts.code, "payer.cpf_cnpj");
        assert!(parts.message.contains("não pode ficar em branco"));
    }
}
