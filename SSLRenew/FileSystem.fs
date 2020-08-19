module SSLRenew.FileSystem

open System.IO
open SSLRenew.Environment

let createValidationFile (env: IEnv) path content =
    let fullPath =
        Path.Join(env.Configuration.ProjectRootPath, path)

    let directoryPath = Path.GetDirectoryName fullPath
    if Directory.Exists directoryPath then Directory.Delete(directoryPath, true)
    Directory.CreateDirectory directoryPath |> ignore
    File.WriteAllText(fullPath, content)

let updateCertificateAndPrivateKey (env: IEnv) certificateContent privateKeyContent =
    File.WriteAllText(env.Configuration.CertificatePath, certificateContent)
    File.WriteAllText(env.Configuration.PrivateKeyPath, privateKeyContent)