module SSLRenew.Program


open System
open FsToolkit.ErrorHandling
open Logary.Configuration
open Logary.Configuration
open Microsoft.Extensions.Configuration
open Hocon.Extensions.Configuration
open System.IO
open Microsoft.VisualBasic
open Newtonsoft.Json
open SSLRenew.Environment
open Logary
open Logary.Message
open Logary.Configuration
open Logary.Targets
open Serilog
open FsHttp

open FsHttp.DslCE


[<Literal>]
let settingsPath = "appsettings.json"

let buildConfig () =
    try
        let settingsStr = File.ReadAllText settingsPath
        Ok
        <| JsonConvert.DeserializeObject<Configuration> settingsStr
    with e ->
        Result.Error
        <| sprintf "File not found or not correct. Message %s" e.Message

let createEnv () =
    let logger =
        let log =
            LoggerConfiguration().WriteTo.Console().CreateLogger()

        { new Environment.ILogger with
            member __.LogInformation(message) = log.Information(message)
            member __.LogError(message) = log.Error(message) }

    match buildConfig () with
    | Ok config ->
        logger.LogInformation(sprintf "Environment created. Configuration %O" config)
        { new IEnv with
            member __.Configuration = config
            member __.Logger = logger }
    | Result.Error error ->
        logger.LogError(error)
        failwithf "Error to build configuration. Error: %s" error

let rec loop failedCount (env: IEnv) =
    async {
        if failedCount > env.Configuration.RetryCount then
            env.Logger.LogError("To many retries")
        else
            match! Renew.needToRenew env DateTime.Now with
            | Ok () -> do! loop 0 env
            | Result.Error error ->
                env.Logger.LogError(sprintf "Error: %s" error)
                do! loop (failedCount + 1) env
    }

let renewRun () =
    asyncResult {
        let env = createEnv ()
        do! loop 0 env
    }


[<EntryPoint>]
let main argv =
    renewRun () |> Async.RunSynchronously |> ignore
    0
