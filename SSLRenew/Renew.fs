module SSLRenew.Renew

open System
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


let createDomainStep (env: IEnv) =
    asyncResult {
        let privateKey, csr = getPrivateKeyAndCsr env

        let! createDomainResult = Api.createDomain env env.Configuration.Domains csr

        let validation = createDomainResult.Validation.OtherMethods.Values.First()

        let content = String.Join(Environment.NewLine, validation.FileValidationContent)

        let path = Uri(validation.FileValidationUrlHttp).LocalPath.Replace("/", "\\")

        FileSystem.createValidationFile env path content

        return privateKey, createDomainResult.Id
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

let renewCertificate (env: IEnv) =
    asyncResult {
        let! privateKey, certificateId = createDomainStep env

        env.Logger.LogInformation(sprintf "Certificate created %s" certificateId)

        do! Api.verifyDomains env certificateId

        env.Logger.LogInformation(sprintf "Certificate verified %s" certificateId)

        do! downloadCertificatesStep env certificateId privateKey

        env.Logger.LogInformation(sprintf "Certificate downloaded %s" certificateId)
    }

[<Literal>]
let wellKnownFolder = ".well-known"

let getWellKnownFile (env: IEnv) =
    let wellKnowPath = Path.Join(env.Configuration.ProjectRootPath, wellKnownFolder)

    if Directory.Exists wellKnowPath then
        let wellKnownFiles = Directory.GetFiles(wellKnowPath, "*.txt", SearchOption.AllDirectories)
        if wellKnownFiles.Length > 1 then Result.Error "More then one file" else Ok(wellKnownFiles |> Seq.tryHead)
    else
        Ok None

let needToRenew (env: IEnv) (now: DateTime) =
    asyncResult {
        env.Logger.LogInformation("Check for renew")
        let! filePath = getWellKnownFile env

        match filePath with
        | Some filePath ->
            let! certificates = Api.getCertificates env [ Api.CertificateStatus.Issued ]
            let fileName = Path.GetFileName filePath

            let certificateWithThisFile =
                certificates.Results
                |> Seq.tryFind (fun c ->
                    c.Validation.OtherMethods.First().Value.FileValidationUrlHttp.Contains(fileName))

            match certificateWithThisFile with
            | Some cert ->
                let totalMillisecondsUntilRun =
                    min (cert.Expires.AddSeconds(5.) - now).TotalMilliseconds 0.
                    |> int

                do! Async.Sleep totalMillisecondsUntilRun
                File.Delete filePath
                do! renewCertificate env
            | None ->
                File.Delete filePath
                do! renewCertificate env
        | None -> do! renewCertificate env
    }
