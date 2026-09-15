// Generated from the frozen method table.
pub struct ApiRoute {
    pub method: u8,
    pub verb: &'static str,
    pub path: &'static str,
}
pub const API_ROUTES: [ApiRoute; 15] = [
    ApiRoute { method: 1, verb: "GET", path: "/v1/capabilities" },
    ApiRoute { method: 2, verb: "POST", path: "/v1/keys/public" },
    ApiRoute { method: 3, verb: "POST", path: "/v1/keys/prepare" },
    ApiRoute { method: 4, verb: "POST", path: "/v1/keys/stage" },
    ApiRoute { method: 5, verb: "POST", path: "/v1/sign" },
    ApiRoute { method: 6, verb: "POST", path: "/v1/requests/result" },
    ApiRoute { method: 7, verb: "POST", path: "/v1/keys/retire" },
    ApiRoute { method: 8, verb: "POST", path: "/rpc/validatorAuth/v1/getProfile" },
    ApiRoute { method: 9, verb: "POST", path: "/rpc/validatorAuth/v1/getPolicy" },
    ApiRoute { method: 10, verb: "POST", path: "/rpc/validatorAuth/v1/getRegistry" },
    ApiRoute { method: 11, verb: "POST", path: "/rpc/validatorAuth/v1/getKey" },
    ApiRoute { method: 12, verb: "POST", path: "/rpc/validatorAuth/v1/getCertificate" },
    ApiRoute { method: 13, verb: "POST", path: "/rpc/validatorAuth/v1/verifyCertificate" },
    ApiRoute { method: 14, verb: "POST", path: "/v1/objects/chunk" },
    ApiRoute { method: 15, verb: "POST", path: "/v1/objects/putChunk" },
];
