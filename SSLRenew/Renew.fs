module SSLRenew.Renew

open System
open System.Threading.Tasks
open FsToolkit.ErrorHandling
open System.IO
open System.Linq
open Logary
open SSLRenew.Environment
open Logary
open Logary.Message
open Logary.Configuration
open Logary.Targets

let getPrivateKeyAndCsr (env: IEnv) =
    if not (String.IsNullOrEmpty env.Configuration.PrivateKey)
       && not (String.IsNullOrEmpty env.Configuration.Certificate) then
        env.Configuration.PrivateKey, env.Configuration.Certificate
    else
        let privateKey, cryptoKey = CSR.generateRsaKeyPair ()
        let csrData = env.Configuration.Csr

        let csr =
            CSR.generateCsr
                cryptoKey
                csrData.Country
                csrData.State
                csrData.Locality
                csrData.Organization
                csrData.OrganizationUnit
                csrData.Common

        privateKey, csr


let createDomainStep (cert: Api.Results option) (env: IEnv) =
    asyncResult {
        let privateKey, csr = getPrivateKeyAndCsr env

        let getValidation () =
            asyncResult {
                match cert with
                | Some c ->
                    if c.Status = "issued" || c.Status = "pending_validation" then
                        return c.Validation.OtherMethods.Values.First(), c.Id
                    elif c.Status = "draft" then
                        let! createDomainResult = Api.createDomain env env.Configuration.Domain csr
                        return createDomainResult.Validation.OtherMethods.Values.First(), createDomainResult.Id
                    else
                        return failwith "Unknown status"
                | None ->
                    let! createDomainResult = Api.createDomain env env.Configuration.Domain csr
                    return createDomainResult.Validation.OtherMethods.Values.First(), createDomainResult.Id
            }

        let! validation, certificateId = getValidation ()
        let content = String.Join(Environment.NewLine, validation.FileValidationContent)

        let path =
            Uri(validation.FileValidationUrlHttp).LocalPath.Replace("\\", Path.DirectorySeparatorChar.ToString())
                .Replace("/", Path.DirectorySeparatorChar.ToString())

        FileSystem.createValidationFile env path content
        return privateKey, certificateId
    }

let downloadCertificatesStep env id privateKey =
    asyncResult {
        let! downloadCertificatesResult = Api.downloadCertificates env id

        let mergeCtrAndBundle =
            sprintf
                "%s%s%s"
                downloadCertificatesResult.Certificatecrt
                Environment.NewLine
                downloadCertificatesResult.CaBundlecrt

        FileSystem.updateCertificateAndPrivateKey env mergeCtrAndBundle privateKey
    }

let renewCertificate results (env: IEnv) =
    asyncResult {
        let! privateKey, certificateId = createDomainStep results env

        env.Logger.LogInformation(sprintf "Certificate created %s" certificateId)

        do! Api.verifyDomains env certificateId

        env.Logger.LogInformation(sprintf "Certificate verified %s" certificateId)

        do! downloadCertificatesStep env certificateId privateKey

        env.Logger.LogInformation(sprintf "Certificate downloaded %s" certificateId)
    }

[<Literal>]
let wellKnownFolder = ".well-known"

let isWellKnownFileExists (env: IEnv) =
    let wellKnowPath = Path.Join(env.Configuration.ProjectRootPath, wellKnownFolder)
    if Directory.Exists wellKnowPath then
        let wellKnownFiles = Directory.GetFiles(wellKnowPath, "*.txt", SearchOption.AllDirectories)
        if wellKnownFiles.Length > 1 then Result.Error "More then one file" else Ok(wellKnownFiles |> Seq.tryHead)
    else
        Ok None

let needToRenew (env: IEnv) (now: DateTime) =
    asyncResult {
        env.Logger.LogInformation("Check for renew")
        let! certificates =
            Api.getCertificates
                env
                [ Api.CertificateStatus.Draft
                  Api.CertificateStatus.Issued
                  Api.CertificateStatus.PendingValidation ]

        let certificateWithThisFile =
            certificates.Results
            |> Seq.tryFind (fun c ->
                c.Validation.OtherMethods.First().Value.FileValidationUrlHttp.Contains(env.Configuration.Domain))

        do! renewCertificate certificateWithThisFile env
        do! Async.Sleep 3_600_000
    }
