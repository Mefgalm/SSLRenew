module SSLRenew.Environment

open System.Collections.Generic

type Csr =
    { Country: string
      State: string
      Locality: string
      Organization: string
      OrganizationUnit: string
      Common: string }

type Configuration =
    { Csr: Csr
      ZeroSSLKey: string
      PrivateKey: string
      Certificate: string
      Domains: IEnumerable<string>
      ProjectRootPath: string
      CertificatePath: string
      PrivateKeyPath: string
      RetryCount: int }


type ILogger =
    abstract LogInformation: string -> unit
    abstract LogError: string -> unit

type IEnv =
    abstract Configuration: Configuration
    abstract Logger: ILogger
