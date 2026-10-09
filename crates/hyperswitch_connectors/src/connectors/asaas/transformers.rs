use std::collections::HashMap;

use common_enums::enums;
use common_utils::{request::Method, types::FloatMajorUnit};
use error_stack::ResultExt;
use hyperswitch_domain_models::{
    payment_method_data::{BankTransferData, Card, PaymentMethodData, VoucherData},
    router_data::{ConnectorAuthType, PaymentMethodToken, RouterData},
    router_flow_types::refunds::{Execute, RSync},
    router_request_types::ResponseId,
    router_response_types::{
        ConnectorCustomerResponseData, MandateReference, PaymentsResponseData, RedirectForm,
        RefundsResponseData,
    },
    types::{ConnectorCustomerRouterData, PaymentsAuthorizeRouterData, RefundsRouterData},
};
use hyperswitch_interfaces::errors;
use hyperswitch_masking::{PeekInterface, Secret};
use serde::{Deserialize, Serialize};

use crate::{
    types::{RefundsResponseRouterData, ResponseRouterData},
    utils::{CardData, CustomerData, PaymentsAuthorizeRequestData, RouterData as _},
};

pub struct AsaasRouterData<T> {
    pub amount: f64,
    pub router_data: T,
}

impl<T> AsaasRouterData<T> {
    pub fn from_major(
        amount: FloatMajorUnit,
        router_data: T,
    ) -> Result<Self, error_stack::Report<errors::ConnectorError>> {
        Ok(Self {
            amount: amount.get_amount_as_f64(),
            router_data,
        })
    }
}

pub struct AsaasAuthType {
    pub(super) api_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for AsaasAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::HeaderKey { api_key } => Ok(Self {
                api_key: api_key.to_owned(),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

/// À vista omits installment fields. Asaas accepts 2 through 21 on Visa and Mastercard.
pub fn asaas_installments(
    installments: Option<u8>,
    total: f64,
) -> Result<(Option<u8>, Option<f64>), error_stack::Report<errors::ConnectorError>> {
    match installments {
        None | Some(0) | Some(1) => Ok((None, None)),
        Some(count) if (2..=21).contains(&count) => Ok((Some(count), Some(total))),
        Some(count) => Err(errors::ConnectorError::NotSupported {
            message: format!(
                "Asaas parcelamento aceita installmentCount de 2 a 21, recebido {count}"
            ),
            connector: "asaas",
        }
        .into()),
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AsaasCustomerRequest {
    name: String,
    cpf_cnpj: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mobile_phone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    postal_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    address_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    external_reference: Option<String>,
}

impl TryFrom<&ConnectorCustomerRouterData> for AsaasCustomerRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &ConnectorCustomerRouterData) -> Result<Self, Self::Error> {
        let request = &item.request;
        let name = request
            .get_optional_name()
            .map(|value| value.peek().to_string())
            .filter(|value| !value.is_empty())
            .ok_or(errors::ConnectorError::MissingRequiredField { field_name: "name" })?;
        let cpf_cnpj =
            document_number(item).ok_or(errors::ConnectorError::MissingRequiredField {
                field_name: "cpfCnpj",
            })?;
        let billing = item
            .get_optional_billing()
            .and_then(|address| address.address.as_ref());
        let phone = item
            .get_optional_billing()
            .and_then(|address| address.phone.as_ref())
            .and_then(|phone| phone.number.as_ref())
            .map(|number| digits_only(number.peek()));
        Ok(Self {
            name,
            cpf_cnpj,
            email: request
                .get_optional_email()
                .map(|email| email.peek().to_string()),
            mobile_phone: phone,
            postal_code: billing
                .and_then(|address| address.zip.as_ref())
                .map(|zip| digits_only(zip.peek())),
            address: billing
                .and_then(|address| address.line1.as_ref())
                .map(|line| line.peek().to_string()),
            address_number: billing
                .and_then(|address| address.line2.as_ref())
                .map(|line| line.peek().to_string()),
            external_reference: request
                .customer_id
                .as_ref()
                .map(|customer_id| customer_id.get_string_repr().to_string()),
        })
    }
}

fn document_number(item: &ConnectorCustomerRouterData) -> Option<String> {
    item.request
        .payment_method_data
        .as_ref()
        .and_then(document_from_payment_method)
        .or_else(|| {
            item.request
                .metadata
                .as_ref()
                .and_then(|metadata| metadata_digits(Some(metadata.peek())))
        })
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AsaasCustomerResponse {
    id: String,
}

impl<F, T> TryFrom<ResponseRouterData<F, AsaasCustomerResponse, T, PaymentsResponseData>>
    for RouterData<F, T, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: ResponseRouterData<F, AsaasCustomerResponse, T, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(PaymentsResponseData::ConnectorCustomerResponse(
                ConnectorCustomerResponseData::new_with_customer_id(item.response.id),
            )),
            ..item.data
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AsaasCard {
    holder_name: Secret<String>,
    number: Secret<String>,
    expiry_month: Secret<String>,
    expiry_year: Secret<String>,
    ccv: Secret<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AsaasHolder {
    name: String,
    email: String,
    cpf_cnpj: String,
    postal_code: String,
    address_number: String,
    phone: String,
}

fn card_payload(card: &Card) -> Result<AsaasCard, error_stack::Report<errors::ConnectorError>> {
    Ok(AsaasCard {
        holder_name: card.get_cardholder_name()?,
        number: Secret::new(card.card_number.get_card_no()),
        expiry_month: card.get_card_expiry_month_2_digit()?,
        expiry_year: card.get_expiry_year_4_digit(),
        ccv: card.card_cvc.clone(),
    })
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AsaasPaymentRequest {
    customer: String,
    billing_type: &'static str,
    value: f64,
    due_date: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    external_reference: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    installment_count: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    total_value: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    credit_card: Option<AsaasCard>,
    #[serde(skip_serializing_if = "Option::is_none")]
    credit_card_holder_info: Option<AsaasHolder>,
    #[serde(skip_serializing_if = "Option::is_none")]
    credit_card_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    authorize_only: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    remote_ip: Option<String>,
}

impl TryFrom<&AsaasRouterData<&PaymentsAuthorizeRouterData>> for AsaasPaymentRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &AsaasRouterData<&PaymentsAuthorizeRouterData>) -> Result<Self, Self::Error> {
        let request = &item.router_data.request;
        let customer = item.router_data.connector_customer.clone().ok_or(
            errors::ConnectorError::MissingRequiredField {
                field_name: "connector_customer",
            },
        )?;
        let due_date = boleto_due_date(&request.payment_method_data).unwrap_or_else(today);
        let (billing_type, card) = match request.payment_method_data.clone() {
            // Asaas only accepts submitted card data under billingType "CREDIT_CARD".
            // There is no "DEBIT_CARD" billingType for API-submitted card data; debit
            // can only be collected via Asaas's hosted invoiceUrl flow. Do not branch
            // this on PaymentMethodType::Debit (see asaas.rs's feature matrix, where
            // Card/Debit is intentionally NotSupported for the same reason).
            PaymentMethodData::Card(card) => ("CREDIT_CARD", Some(card)),
            PaymentMethodData::MandatePayment => ("CREDIT_CARD", None),
            PaymentMethodData::BankTransfer(transfer) if is_pix(transfer.as_ref()) => ("PIX", None),
            PaymentMethodData::Voucher(VoucherData::Boleto(_)) => ("BOLETO", None),
            _ => {
                return Err(errors::ConnectorError::NotSupported {
                    message: "forma de pagamento não suportada pelo Asaas".to_string(),
                    connector: "asaas",
                }
                .into());
            }
        };
        let (installment_count, total_value) = if billing_type == "CREDIT_CARD" {
            asaas_installments(
                request
                    .installment_details
                    .as_ref()
                    .map(|details| details.number_of_installments.get()),
                item.amount,
            )?
        } else {
            (None, None)
        };
        let stored = stored_token(item.router_data);
        let (credit_card, credit_card_holder_info, credit_card_token, remote_ip, authorize_only) =
            if billing_type == "CREDIT_CARD" {
                let remote_ip = payer_ip(item.router_data)?;
                let authorize_only = Some(!request.is_auto_capture()?);
                match (stored, card) {
                    (Some(token), _) => (None, None, Some(token), Some(remote_ip), authorize_only),
                    (None, Some(card)) => (
                        Some(card_payload(&card)?),
                        Some(holder_from_router(item.router_data, &card)?),
                        None,
                        Some(remote_ip),
                        authorize_only,
                    ),
                    (None, None) => {
                        return Err(errors::ConnectorError::MissingRequiredField {
                            field_name: "creditCardToken",
                        }
                        .into());
                    }
                }
            } else {
                (None, None, None, None, None)
            };
        Ok(Self {
            customer,
            billing_type,
            value: item.amount,
            due_date,
            description: item.router_data.description.clone(),
            external_reference: item.router_data.connector_request_reference_id.clone(),
            installment_count,
            total_value,
            credit_card,
            credit_card_holder_info,
            credit_card_token,
            authorize_only,
            remote_ip,
        })
    }
}

fn is_pix(data: &BankTransferData) -> bool {
    matches!(
        data,
        BankTransferData::Pix { .. } | BankTransferData::PixQr {} | BankTransferData::PixEmv {}
    )
}

fn stored_token(item: &PaymentsAuthorizeRouterData) -> Option<String> {
    if let Some(PaymentMethodToken::Token(token)) = &item.payment_method_token {
        return Some(token.peek().to_string());
    }
    item.request.connector_mandate_id()
}

fn payer_ip(
    item: &PaymentsAuthorizeRouterData,
) -> Result<String, error_stack::Report<errors::ConnectorError>> {
    item.request
        .get_ip_address_as_optional()
        .map(|ip| ip.peek().to_string())
        .filter(|ip| !ip.is_empty())
        .ok_or_else(|| {
            errors::ConnectorError::MissingRequiredField {
                field_name: "browser_info.ip_address",
            }
            .into()
        })
}

fn holder_from_router(
    item: &PaymentsAuthorizeRouterData,
    card: &Card,
) -> Result<AsaasHolder, error_stack::Report<errors::ConnectorError>> {
    let name = card
        .get_cardholder_name()
        .ok()
        .map(|value| value.peek().to_string())
        .or_else(|| {
            item.request
                .customer_name
                .as_ref()
                .map(|value| value.peek().to_string())
        })
        .ok_or(errors::ConnectorError::MissingRequiredField {
            field_name: "card_holder_name",
        })?;
    let email = item
        .request
        .get_optional_email()
        .or_else(|| item.get_optional_billing_email())
        .map(|email| email.peek().to_string())
        .ok_or(errors::ConnectorError::MissingRequiredField {
            field_name: "email",
        })?;
    let cpf_cnpj = document_from_payment_method(&item.request.payment_method_data)
        .or_else(|| metadata_digits(item.request.metadata.as_ref()))
        .filter(|value| !value.is_empty())
        .ok_or(errors::ConnectorError::MissingRequiredField {
            field_name: "cpfCnpj",
        })?;
    let postal_code = item
        .get_optional_billing_zip()
        .map(|zip| digits_only(zip.peek()))
        .filter(|value| !value.is_empty())
        .ok_or(errors::ConnectorError::MissingRequiredField {
            field_name: "billing.address.zip",
        })?;
    let address_number = item
        .get_optional_billing_line2()
        .map(|line| line.peek().to_string())
        .filter(|value| !value.is_empty())
        .ok_or(errors::ConnectorError::MissingRequiredField {
            field_name: "billing.address.line2",
        })?;
    let phone = item
        .get_optional_billing_phone_number()
        .map(|phone| digits_only(phone.peek()))
        .filter(|value| !value.is_empty())
        .ok_or(errors::ConnectorError::MissingRequiredField {
            field_name: "billing.phone",
        })?;
    Ok(AsaasHolder {
        name,
        email,
        cpf_cnpj,
        postal_code,
        address_number,
        phone,
    })
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

fn boleto_due_date(data: &PaymentMethodData) -> Option<String> {
    match data {
        PaymentMethodData::Voucher(VoucherData::Boleto(boleto)) => boleto.due_date.clone(),
        _ => None,
    }
}

fn today() -> String {
    time::OffsetDateTime::now_utc().date().to_string()
}

fn digits_only(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_digit())
        .collect()
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AsaasPaymentStatus {
    Pending,
    Received,
    Confirmed,
    Overdue,
    Refunded,
    ReceivedInCash,
    RefundRequested,
    RefundInProgress,
    ChargebackRequested,
    ChargebackDispute,
    AwaitingChargebackReversal,
    DunningRequested,
    DunningReceived,
    AwaitingRiskAnalysis,
    Authorized,
    #[serde(other)]
    Unknown,
}

impl From<AsaasPaymentStatus> for enums::AttemptStatus {
    fn from(status: AsaasPaymentStatus) -> Self {
        match status {
            AsaasPaymentStatus::Received
            | AsaasPaymentStatus::Confirmed
            | AsaasPaymentStatus::ReceivedInCash
            | AsaasPaymentStatus::RefundRequested
            | AsaasPaymentStatus::RefundInProgress => Self::Charged,
            AsaasPaymentStatus::Authorized => Self::Authorized,
            AsaasPaymentStatus::Pending
            | AsaasPaymentStatus::AwaitingRiskAnalysis
            | AsaasPaymentStatus::DunningRequested
            | AsaasPaymentStatus::DunningReceived => Self::AuthenticationPending,
            AsaasPaymentStatus::Refunded => Self::AutoRefunded,
            AsaasPaymentStatus::Overdue
            | AsaasPaymentStatus::ChargebackRequested
            | AsaasPaymentStatus::ChargebackDispute
            | AsaasPaymentStatus::AwaitingChargebackReversal => Self::Failure,
            AsaasPaymentStatus::Unknown => Self::Pending,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AsaasPaymentsResponse {
    id: String,
    status: AsaasPaymentStatus,
    #[serde(default)]
    invoice_url: Option<String>,
    #[serde(default)]
    bank_slip_url: Option<String>,
    #[serde(default)]
    nosso_numero: Option<String>,
    #[serde(default)]
    credit_card: Option<AsaasCardToken>,
    #[serde(default)]
    refunds: Vec<AsaasRefundItem>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AsaasCardToken {
    #[serde(default)]
    credit_card_token: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AsaasRefundStatus {
    Pending,
    AwaitingCriticalActionAuthorization,
    AwaitingCustomerExternalAuthorization,
    Cancelled,
    Done,
    #[serde(other)]
    Unknown,
}

impl From<AsaasRefundStatus> for enums::RefundStatus {
    fn from(status: AsaasRefundStatus) -> Self {
        match status {
            AsaasRefundStatus::Done => Self::Success,
            AsaasRefundStatus::Cancelled => Self::Failure,
            AsaasRefundStatus::Pending
            | AsaasRefundStatus::AwaitingCriticalActionAuthorization
            | AsaasRefundStatus::AwaitingCustomerExternalAuthorization
            | AsaasRefundStatus::Unknown => Self::Pending,
        }
    }
}

#[derive(Debug, Deserialize, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AsaasRefundItem {
    id: String,
    status: AsaasRefundStatus,
    #[serde(default)]
    value: Option<f64>,
    #[serde(default)]
    date_created: Option<String>,
}

impl<F, T> TryFrom<ResponseRouterData<F, AsaasPaymentsResponse, T, PaymentsResponseData>>
    for RouterData<F, T, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: ResponseRouterData<F, AsaasPaymentsResponse, T, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let mandate = item
            .response
            .credit_card
            .as_ref()
            .and_then(|card| card.credit_card_token.clone())
            .map(|connector_mandate_id| MandateReference {
                connector_mandate_id: Some(connector_mandate_id),
                payment_method_id: None,
                mandate_metadata: None,
                connector_mandate_request_reference_id: None,
            });
        let connector_metadata =
            if item.response.bank_slip_url.is_some() || item.response.nosso_numero.is_some() {
                Some(serde_json::json!({
                    "bank_slip_url": item.response.bank_slip_url,
                    "nosso_numero": item.response.nosso_numero,
                    "invoice_url": item.response.invoice_url,
                }))
            } else if item.response.invoice_url.is_some() {
                Some(serde_json::json!({ "invoice_url": item.response.invoice_url }))
            } else {
                None
            };
        let redirect = item
            .response
            .bank_slip_url
            .clone()
            .or(item.response.invoice_url.clone())
            .map(|endpoint| RedirectForm::Form {
                endpoint,
                method: Method::Get,
                form_fields: HashMap::new(),
            });
        Ok(Self {
            status: enums::AttemptStatus::from(item.response.status),
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id.clone()),
                redirection_data: Box::new(redirect),
                mandate_reference: Box::new(mandate),
                connector_metadata,
                network_txn_id: None,
                network_txn_link_id: None,
                connector_response_reference_id: Some(item.response.id),
                incremental_authorization_allowed: None,
                authentication_data: None,
                charges: None,
            }),
            ..item.data
        })
    }
}

#[derive(Debug, Serialize)]
pub struct AsaasRefundRequest {
    value: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
}

impl<F> TryFrom<&AsaasRouterData<&RefundsRouterData<F>>> for AsaasRefundRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &AsaasRouterData<&RefundsRouterData<F>>) -> Result<Self, Self::Error> {
        Ok(Self {
            value: item.amount,
            description: item.router_data.request.reason.clone(),
        })
    }
}

#[derive(Debug, Serialize)]
pub struct AsaasCaptureRequest {}

pub struct AsaasRefundSync {
    pub connector_refund_id: String,
    pub refund_status: enums::RefundStatus,
}

impl AsaasPaymentsResponse {
    pub fn refund_state(
        &self,
        connector_refund_id: Option<&str>,
        expected_value: Option<f64>,
    ) -> AsaasRefundSync {
        let by_id = connector_refund_id
            .and_then(|id| self.refunds.iter().find(|refund| refund.id == id));
        let by_value = by_id.or_else(|| {
            expected_value.and_then(|value| {
                self.refunds
                    .iter()
                    .filter(|refund| {
                        refund
                            .value
                            .is_some_and(|refund_value| (refund_value - value).abs() < 0.005)
                    })
                    .max_by(|a, b| a.date_created.cmp(&b.date_created))
            })
        });
        let refund = by_value.or_else(|| self.refunds.last());
        if let Some(refund) = refund {
            return AsaasRefundSync {
                connector_refund_id: refund.id.clone(),
                refund_status: enums::RefundStatus::from(refund.status),
            };
        }
        AsaasRefundSync {
            connector_refund_id: self.id.clone(),
            refund_status: if self.status == AsaasPaymentStatus::Refunded {
                enums::RefundStatus::Success
            } else {
                enums::RefundStatus::Pending
            },
        }
    }
}

impl TryFrom<RefundsResponseRouterData<Execute, AsaasPaymentsResponse>>
    for RefundsRouterData<Execute>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: RefundsResponseRouterData<Execute, AsaasPaymentsResponse>,
    ) -> Result<Self, Self::Error> {
        let expected_value = item
            .data
            .request
            .minor_refund_amount
            .to_major_unit_as_f64(item.data.request.currency)
            .change_context(errors::ConnectorError::AmountConversionFailed)
            .ok()
            .map(|amount| amount.get_amount_as_f64());
        let state = item.response.refund_state(None, expected_value);
        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: state.connector_refund_id,
                refund_status: state.refund_status,
            }),
            ..item.data
        })
    }
}

impl TryFrom<RefundsResponseRouterData<RSync, AsaasPaymentsResponse>> for RefundsRouterData<RSync> {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: RefundsResponseRouterData<RSync, AsaasPaymentsResponse>,
    ) -> Result<Self, Self::Error> {
        let state = item
            .response
            .refund_state(item.data.request.connector_refund_id.as_deref(), None);
        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: state.connector_refund_id,
                refund_status: state.refund_status,
            }),
            ..item.data
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AsaasErrorResponse {
    #[serde(default)]
    pub errors: Vec<AsaasErrorItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsaasErrorItem {
    #[serde(default)]
    pub code: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayErrorParts {
    pub code: String,
    pub message: String,
}

pub fn gateway_error_from_asaas(errors: &[AsaasErrorItem]) -> GatewayErrorParts {
    let code = errors
        .first()
        .map(|error| error.code.clone())
        .filter(|code| !code.is_empty())
        .unwrap_or_else(|| "asaas_error".to_string());
    let message = errors
        .iter()
        .map(|error| error.description.clone())
        .filter(|description| !description.is_empty())
        .collect::<Vec<_>>()
        .join("; ");
    GatewayErrorParts {
        code,
        message: if message.is_empty() {
            "recusa do Asaas".to_string()
        } else {
            message
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{asaas_installments, gateway_error_from_asaas, AsaasErrorItem, AsaasPaymentStatus};

    #[test]
    fn avista_omits_installments_and_twelve_sends_total() {
        assert_eq!(asaas_installments(None, 10.0).unwrap(), (None, None));
        assert_eq!(asaas_installments(Some(1), 10.0).unwrap(), (None, None));
        assert_eq!(
            asaas_installments(Some(12), 120.0).unwrap(),
            (Some(12), Some(120.0))
        );
        assert!(asaas_installments(Some(22), 10.0).is_err());
    }

    #[test]
    fn decline_keeps_gateway_code_and_description() {
        let parts = gateway_error_from_asaas(&[AsaasErrorItem {
            code: "invalid_creditCard".to_string(),
            description: "Transação não autorizada".to_string(),
        }]);
        assert_eq!(parts.code, "invalid_creditCard");
        assert_eq!(parts.message, "Transação não autorizada");
        assert_eq!(
            common_enums::AttemptStatus::from(AsaasPaymentStatus::Authorized),
            common_enums::AttemptStatus::Authorized
        );
    }
}
