use std::{collections::HashMap, ops::Deref, sync::Arc, time::Duration};

use super::{
    expiration::{ExpirationManager, DEFAULT_LEASE_DURATION_SECS, MAX_LEASE_DURATION_SECS},
    TokenStore, AUTH_ROUTER_PREFIX,
};
use crate::{
    core::Core,
    errors::RvError,
    handler::Handler,
    logical::{
        Auth, Backend, Field, FieldType, Lease, LogicalBackend, Operation, Path, PathOperation, Request, Response,
    },
    new_fields, new_fields_internal, new_logical_backend, new_logical_backend_internal, new_path, new_path_internal,
    router::Router,
    storage::{Storage, StorageEntry},
    utils::{cert, cert::CertBundle, generate_uuid, is_str_subset, sha1},
};

use humantime::parse_duration;
use lazy_static::lazy_static;
use openssl::{
    pkey::{Id, PKey},
    x509::{X509Ref, X509VerifyResult, X509},
};
use pem;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

const KUBERNETES_SUB_PATH: &str = "kubernetes/";
//what does this do?
const KUBERNETES_SALT_LOCATION: &str = "salt";

pub struct KubernetesStoreInner {
    pub router: Arc<Router>,
    pub view: Option<Arc<dyn Storage + Send + Sync>>,
    pub salt: String,
    pub expiration: Arc<ExpirationManager>,
}

impl Default for KubernetesStoreInner {
    fn default() -> Self {
        Self {
            router: Arc::new(Router::new()),
            view: None,
            salt: String::new(),
            expiration: Arc::new(ExpirationManager::default()),
        }
    }
}

pub struct KubernetesStore {
    pub inner: Arc<KubernetesStoreInner>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KubernetesConfigEntry {
    pub kubernetes_host: String,
    #[serde(default = "String::new")]
    pub kubernetes_ca_cert: String,
    #[serde(default = "String::new")]
    pub token_reviewer_jwt: String,
    #[serde(default = "Vec::new")]
    pub pem_keys: Vec<String>,
    #[serde(default = "bool::default")]
    pub disable_local_ca_jwt: bool,
    #[serde(default = "bool::default")]
    pub disable_iss_validation: bool,
    #[serde(default = "String::new")]
    pub issuer: String,
}

pub struct KubernetesRoleEntry {
    pub name: String,
    pub bound_service_account_names: Vec<String>,
    pub bound_service_account_namespaces: Vec<String>,
    pub audience: String,
    pub alias_name_source: String,
    pub token_ttl: String,
    pub ttl: String,
    pub token_max_ttl: String,
    pub max_ttl: String,
    pub token_policies: Vec<String>,
    pub policies: Vec<String>,
    pub token_bound_cidrs: Vec<String>,
    pub bound_cidrs: Vec<String>,
    pub token_explicit_max_ttl: String,
    pub token_no_default_policy: bool,
    pub token_num_uses: i32,
    pub num_uses: i32,
    pub token_period: String,
    pub period: String,
    pub token_type: String,
}

impl KubernetesStore {
    pub fn new(core: &Core, expiration: Arc<ExpirationManager>) -> Result<KubernetesStore, RvError> {
        if core.system_view.is_none() {
            return Err(RvError::ErrBarrierSealed);
        }

        let mut inner = KubernetesStoreInner::default();
        let view = core.system_view.as_ref().unwrap().new_sub_view(KUBERNETES_SUB_PATH);
        let salt = view.as_storage().get(KUBERNETES_SALT_LOCATION)?;

        if salt.is_some() {
            inner.salt = String::from_utf8_lossy(&salt.unwrap().value).to_string();
        }

        if inner.salt.as_str() == "" {
            inner.salt = generate_uuid();
            let raw = StorageEntry { key: KUBERNETES_SALT_LOCATION.to_string(), value: inner.salt.as_bytes().to_vec() };
            view.as_storage().put(&raw)?;
        }

        inner.router = Arc::clone(&core.router);
        inner.view = Some(Arc::new(view));
        inner.expiration = expiration;

        Ok(KubernetesStore { inner: Arc::new(inner) })
    }

    pub fn new_backend(&self) -> LogicalBackend {
        let handle_write_config = Arc::clone(&self.inner);
        let handle_read_config = Arc::clone(&self.inner);
        let handle_write_role = Arc::clone(&self.inner);

        let backend = new_logical_backend!({
            paths: [
                {
                    pattern: "config",
                    fields: {
                        "kubernetes_host": {
                            field_type: FieldType::Str,
                            description: "Host must be a host string, a host:port pair, or a URL to the base of the Kubernetes API server."
                        },
                        "kubernetes_ca_cert": {
                            field_type: FieldType::Str,
                            description: "PEM encoded CA cert for use by the TLS client used to talk with the Kubernetes API.",
                            required: false,
                            default: ""
                        },
                        "token_reviewer_jwt": {
                            field_type: FieldType::Str,
                            description: "TokenReviewer JWT",
                            required: false,
                            default: ""
                        },
                        "pem_keys": {
                            field_type: FieldType::Map,
                            description: "PEM encoded public key used to verify the signatures of Kubernetes service account JWTs. If a certificate is specified, this is not used.",
                            required: false,
                            default: ""
                        },
                        "disable_local_ca_jwt": {
                            field_type: FieldType::Bool,
                            description: "Disable JWT verification using the local CA cert. This is useful when the JWTs are signed by a different CA than the local one.",
                            required: false,
                            default: false
                        },
                        "disable_iss_validation": {
                            field_type: FieldType::Bool,
                            description: "Disable issuer validation for the JWT. This is useful when the issuer is different than the local one.",
                            required: false,
                            default: false
                        },
                        "issuer": {
                            field_type: FieldType::Str,
                            description: "Issuer is a string that identifies the issuer of the token. If specified, the issuer field in the token must match the specified value.",
                            required: false,
                            default: ""
                        }
                    },
                    operations: [
                        {op: Operation::Write, handler:  handle_write_config.handle_write_config},
                        {op: Operation::Read, handler:  handle_read_config.handle_read_config},
                    ],
                    help: "The Kubernetes auth method validates service account JWTs and verifies their existence with the Kubernetes TokenReview API. This endpoint configures the public key used to validate the JWT signature and the necessary information to access the Kubernetes API."
                },
                {
                    pattern: "role/(?P<name>.+)",
                    fields: {
                        "name": {
                            field_type: FieldType::Str,
                            description: "The name of the role."
                        },
                        "bound_service_account_names": {
                            field_type: FieldType::Map,
                            description: "List of service account names able to access this role. If bound_service_account_names is set, bound_service_account_namespaces must also be set."
                        },
                        "bound_service_account_namespaces": {
                            field_type: FieldType::Map,
                            description: "List of namespaces allowed to access this role. If bound_service_account_namespaces is set, bound_service_account_names must also be set."
                        },
                        "audience": {
                            field_type: FieldType::Str,
                            description: "Audience claim to validate in the JWT. If set, the aud field in the JWT must match the value.",
                            default: "",
                            required: false
                        },
                        "alias_name_source": {
                            field_type: FieldType::Str,
                            description: "The source of the name to use for the alias. Can be one of 'service-account-name' or 'service-account-uid'.",
                            default: "serviceaccount_uid",
                            required: false
                        },
                        "token_ttl": {
                            field_type: FieldType::Str,
                            description: "The TTL of tokens issued using this role. This is the maximum allowed value. The actual TTL of the token will be the minimum of the TTL of the role and the TTL of the token request.",
                            default: "",
                            required: false
                        },
                        "ttl": {
                            field_type: FieldType::Str,
                            description: "The TTL of tokens issued using this role. This is the maximum allowed value. The actual TTL of the token will be the minimum of the TTL of the role and the TTL of the token request.",
                            default: "",
                            required: false
                        },
                        "token_max_ttl": {
                            field_type: FieldType::Str,
                            description: "The maximum allowed lifetime of tokens issued using this role. This is the maximum allowed value. The actual lifetime of the token will be the minimum of the token_max_ttl of the role and the token_max_ttl of the token request.",
                            default: "",
                            required: false
                        },
                        "max_ttl": {
                            field_type: FieldType::Str,
                            description: "The maximum allowed lifetime of tokens issued using this role. This is the maximum allowed value. The actual lifetime of the token will be the minimum of the token_max_ttl of the role and the token_max_ttl of the token request.",
                            default: "",
                            required: false
                        },
                        "token_policies": {
                            field_type: FieldType::Map,
                            description: "List of token policies to encode onto generated tokens. Depending on the auth method, this list may be supplemented by user/group/other values.",
                            default: "",
                            required: false
                        },
                        "policies": {
                            field_type: FieldType::Map,
                            description: "List of token policies to encode onto generated tokens. Depending on the auth method, this list may be supplemented by user/group/other values.",
                            default: "",
                            required: false
                        },
                        "token_bound_cidrs": {
                            field_type: FieldType::Map,
                            description: "List of CIDR blocks; if set, specifies blocks of IP addresses which can authenticate successfully, and ties the resulting token to these blocks as well.",
                            default: "",
                            required: false
                        },
                        "bound_cidrs": {
                            field_type: FieldType::Map,
                            description: "List of CIDR blocks; if set, specifies blocks of IP addresses which can authenticate successfully, and ties the resulting token to these blocks as well.",
                            default: "",
                            required: false
                        },
                        "token_explicit_max_ttl": {
                            field_type: FieldType::Str,
                            description: "If set, will encode an explicit max TTL onto the token. This is a hard cap even if token_ttl and token_max_ttl would otherwise allow a renewal.",
                            default: "",

                            required: false
                        },
                        "token_no_default_policy": {
                            field_type: FieldType::Bool,
                            description: "If set, the default policy will not be set on generated tokens; otherwise it will be added to the policies set in token_policies.",
                            default: false,
                            required: false
                        },
                        "token_num_uses": {
                            field_type: FieldType::Int,
                            description: "The maximum number of times a token issued against this role can be used. 0 means unlimited uses.",
                            default: 0,
                            required: false
                        },
                        "num_uses": {
                            field_type: FieldType::Int,
                            description: "The maximum number of times a token issued against this role can be used. 0 means unlimited uses.",
                            default: 0,
                            required: false
                        },
                        "token_period": {
                            field_type: FieldType::Str,
                            description: "The period, if any, to set on the token.",
                            default: "",
                            required: false
                        },
                        "period": {
                            field_type: FieldType::Str,
                            description: "The period, if any, to set on the token.",
                            default: "",
                            required: false
                        },
                        "token_type": {
                            field_type: FieldType::Str,
                            description: "The type of token that should be generated. Can be service, batch, or default to use the mount's tuned default.",
                            default: "default",
                            required: false
                        }
                    },
                    operations: [
                        {op: Operation::Write, handler: handle_write_role.handle_write_role},
                    ],
                    help: "Registers a role in the auth method. Role types have specific entities that can perform login operations against this endpoint. Constraints specific to the role type must be set on the role. These are applied to the authenticated entities attempting to login."
                }
            ],
            help: ""
        });

        backend
    }
}

impl KubernetesStoreInner {
    pub fn handle_write_config(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        if req.body.is_none() {
            return Err(RvError::ErrRequestInvalid);
        }

        let mut entry: KubernetesConfigEntry =
            serde_json::from_value(Value::Object(req.body.as_ref().unwrap().clone()))?;

        if entry.kubernetes_host.is_empty() {
            return Err(RvError::ErrKubernetesHostMissing);
        }

        // if the local CA JWT is disabled, the CA cert must be present
        if entry.disable_local_ca_jwt && entry.kubernetes_ca_cert.is_empty() {
            return Err(RvError::ErrKubernetesCaCertMissing);
        }

        // Validate the PEM keys if they are present
        if !entry.pem_keys.is_empty() {
            let mut i = 0;
            let mut key_found = false;
            for key in entry.pem_keys.iter() {
                let item = pem::parse(key)?;

                let mut cert_bundle = CertBundle::default();

                if item.tag() == "CERTIFICATE" {
                    let cert = X509::from_der(item.contents())?;
                    if !cert::is_ca_cert(&cert) {
                        return Err(RvError::ErrKubernetesPemBundleInvalid);
                    }

                    if i == 0 {
                        cert_bundle.certificate = cert;
                    } else {
                        cert_bundle.ca_chain.push(cert);
                    }
                    i += 1;
                }

                if item.tag() == "PRIVATE KEY" {
                    if key_found {
                        return Err(RvError::ErrKubernetesPemBundleInvalid);
                    }
                    cert_bundle.private_key = PKey::private_key_from_der(item.contents())?;
                    match cert_bundle.private_key.id() {
                        Id::RSA => {
                            cert_bundle.private_key_type = "rsa".to_string();
                        }
                        Id::DSA => {
                            cert_bundle.private_key_type = "dsa".to_string();
                        }
                        Id::EC => {
                            cert_bundle.private_key_type = "ec".to_string();
                        }
                        _ => {
                            cert_bundle.private_key_type = "other".to_string();
                        }
                    }
                    key_found = true;
                }
            }
        }

        // update and make sure the kubernetes config is valid.

        // write the config to the storage
        self.write_config(&mut entry)?;

        let resp = Response:: default();
        Ok(Some(resp))
    }

    pub fn write_config(&self, entry: &mut KubernetesConfigEntry) -> Result<(), RvError> {
        if self.view.is_none() {
            return Err(RvError::ErrModuleNotInit);
        }

        let view = self.view.as_ref().unwrap();

        let entry = StorageEntry {
            key: "config".to_string(),
            value: serde_json::to_string(entry)?.as_bytes().to_vec(),
        };

        view.put(&entry)
    }

    // now the response contains extra paramters like the lease_id, renewable, lease_duration
    // it still need to be optimized for the extra parameters
    pub fn handle_read_config(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        if !req.body.is_none() {
            return Err(RvError::ErrKubernetesReadConfigNotSupport);
        }
        let kubernetes_config = self.read_config()?.unwrap();
        let rsp_data = serde_json::json!(kubernetes_config).as_object().unwrap().clone();
        Ok(Some(Response::data_response(Some(rsp_data))))
    }

    pub fn read_config(&self) -> Result<Option<KubernetesConfigEntry>, RvError> {
        if self.view.is_none() {
            return Err(RvError::ErrModuleNotInit);
        }

        let view = self.view.as_ref().unwrap();
        let path = "config";
        let raw = view.get(&path)?;

        if raw.is_none() {
            return Err(RvError::ErrKubernetesConfigMissing);
        }

        let entry: KubernetesConfigEntry = serde_json::from_slice(raw.unwrap().value.as_slice())?;

        Ok(Some(entry))
    }

    pub fn handle_write_role(&self, _backend: &dyn Backend, req: &mut Request) -> Result<Option<Response>, RvError> {
        if req.body.is_none() {
            return Err(RvError::ErrRequestInvalid);
        }

        let role_name = req.path.clone();
        let role_name = role_name.split('/').last().unwrap();

        if role_name.is_empty() {
            return Err(RvError::ErrKubernetesRoleNameMissing);
        }

        match self.view.as_ref().unwrap().get(&role_name).is_ok() {
            true => return Err(RvError::ErrKubernetesRoleAlreadyExists),
            false => (),
        }



        let role = serde_json::from_value(Value::Object(req.body.as_ref().unwrap().clone()))?;

        self.write_role(role_name, &role)?;

        Ok(None)
    }

}
