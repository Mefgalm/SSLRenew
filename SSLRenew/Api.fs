module SSLRenew.Api

open Environment
open System
open System.Collections.Generic
open Newtonsoft.Json
open Newtonsoft.Json.Linq
open FsToolkit.ErrorHandling
open FSharp.Data

type FileValidation =
    { [<JsonProperty("file_validation_url_http")>]
      FileValidationUrlHttp: string

      [<JsonProperty("file_validation_url_https")>]
      FileValidationUrlHttps: string

      [<JsonProperty("file_validation_content")>]
      FileValidationContent: string list }

type Validation =
    { [<JsonProperty("other_methods")>]
      OtherMethods: Dictionary<string, FileValidation> }

type CreateDomainResponse =
    { [<JsonProperty("id")>]
      Id: string

      [<JsonProperty("validation")>]
      Validation: Validation }

type ValidateDomainResponse =
    { [<JsonProperty("id")>]
      Id: string }

type Results =
    { [<JsonProperty("id")>]
      Id: string

      [<JsonProperty("type")>]
      Type: string

      [<JsonProperty("created")>]
      Created: DateTime

      [<JsonProperty("expires")>]
      Expires: DateTime

      [<JsonProperty("status")>]
      Status: string

      [<JsonProperty("validation")>]
      Validation: Validation }

type GetCertificatesResponse =
    { [<JsonProperty("results")>]
      Results: Results list }

type DownloadCertificateResponse =
    { [<JsonProperty("certificate.crt")>]
      Certificatecrt: string

      [<JsonProperty("ca_bundle.crt")>]
      CaBundlecrt: string }

type CertificateStatus =
    | Draft
    | PendingValidation
    | Issued
    | Cancelled
    | ExpiringSoon
    | Expired

[<Literal>]
let baseUrl = "https://api.zerossl.com/certificates"

let private safeApiCall f =
    async {
        try
            let! result = f ()
            return Ok result
        with e -> return Error e.Message
    }

let checkForError (jObject: JObject) =
    let errorToken = jObject.["error"]
    if not (isNull errorToken) && errorToken.HasValues
    then Error <| errorToken.["type"].ToString()
    else Ok()

let createDomain (env: IEnv) (domains: seq<string>) csr =
    asyncResult {
        let! result =
            safeApiCall (fun () ->
                Http.AsyncRequestString
                    (url = baseUrl,
                     query = [ "access_key", env.Configuration.ZeroSSLKey ],
                     httpMethod = "POST",
                     body =
                         FormValues [ "certificate_domains", String.Join(",", domains)
                                      "certificate_validity_days", "90"
                                      "certificate_csr", csr ]))

        let jObject = JObject.Parse result

        do! checkForError jObject
        return JsonConvert.DeserializeObject<CreateDomainResponse> result
    }

let verifyDomains (env: IEnv) id =
    asyncResult {
        let! result =
            safeApiCall (fun () ->
                Http.AsyncRequestString
                    (url = sprintf "%s/%s/challenges" baseUrl id,
                     query = [ "access_key", env.Configuration.ZeroSSLKey ],
                     httpMethod = "POST",
                     body = FormValues [ "validation_method", "HTTP_CSR_HASH" ]))

        let jObject = JObject.Parse result
        do! checkForError jObject
    }

let downloadCertificates (env: IEnv) id =
    asyncResult {
        let! result =
            safeApiCall (fun () ->
                Http.AsyncRequestString
                    (url = sprintf "%s/%s/download/return" baseUrl id,
                     query = [ "access_key", env.Configuration.ZeroSSLKey ],
                     httpMethod = "GET"))

        let jObject = JObject.Parse result
        do! checkForError jObject
        return JsonConvert.DeserializeObject<DownloadCertificateResponse> result
    }

let getCertificates (env: IEnv) (statuses: seq<CertificateStatus>) =
    asyncResult {
        let! result =
            safeApiCall (fun () ->
                Http.AsyncRequestString
                    (url = baseUrl,
                     query =
                         [ "access_key", env.Configuration.ZeroSSLKey
                           "certificate_status", String.Join(",", statuses |> Seq.map (fun x -> x.ToString()))
                           "limit", "100"
                           "page", "1" ],
                     httpMethod = "GET"))

        let jObject = JObject.Parse result
        do! checkForError jObject
        return JsonConvert.DeserializeObject<GetCertificatesResponse> result
    }
