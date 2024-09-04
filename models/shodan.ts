export interface Banner {
  asn?: Asn;
  amqp?: Amqp;
  cpe?: Cpe;
  cpe23?: Cpe23;
  data: Data;
  device?: Device;
  devicetype?: Devicetype;
  domains: Domains;
  hash: Hash;
  hostnames: Hostnames;
  html?: Html;
  ip?: Ip;
  ip_str?: IpStr;
  info?: Info;
  ipv6?: Ipv6;
  isp?: Isp;
  link?: Link;
  mac?: Mac;
  opts?: Opts;
  org?: Org1;
  os?: Os;
  platform?: Platform1;
  port: Port;
  product?: Product1;
  screenshot?: Screenshot;
  tags?: Tag[];
  timestamp: Timestamp;
  title?: Title;
  transport: Transport;
  uptime?: Uptime;
  vendor?: Vendor;
  version?: Version1;
  vulns?: Vulns;
  location?: Location;
  _shodan: _Shodan;
  afp?: Afp;
  airplay?: Airplay;
  android_debug_bridge?: AndroidDebugBridge;
  bacnet?: Bacnet;
  bgp?: Bgp;
  bitcoin?: Bitcoin;
  cassandra?: Cassandra;
  checkpoint?: Checkpoint;
  chromecast?: Chromecast;
  cisco_anyconnect?: CiscoAnyconnect;
  clickhouse?: Clickhouse;
  cloud?: Cloud;
  coap?: Coap;
  cobalt_strike_beacon?: CobaltStrikeBeacon;
  cockroachdb?: Cockroachdb;
  codesys?: CodeSys;
  consul?: Consul;
  couchbase_server?: CouchbaseServer;
  couchbase_sync_gateway?: CouchbaseSyncGateway;
  couchdb?: Couchdb1;
  dahua?: Dahua;
  dahua_dvr_web?: DahuaDvrWeb;
  dav?: Dav;
  dns?: Dns;
  docker?: Docker;
  docker_registry?: DockerRegistry;
  domoticz?: Domoticz;
  draytek_vigor?: DraytekVigor;
  elastic?: Elastic;
  epmd?: Epmd;
  etcd?: Etcd;
  ethereum_p2p?: EthereumP2P;
  ethereum_rpc?: EthereumRpc;
  ethernetip?: Ethernetip;
  fortinet?: Fortinet;
  ftp?: Ftp;
  ganglia?: Ganglia;
  handpunch?: Handpunch;
  hbase?: HBase;
  hikvision?: Hikvision;
  hive?: ApacheHive;
  home_assistant?: HomeAssistant;
  homebridge?: Homebridge;
  hoobs?: Hoobs;
  hp_ilo?: HpIlo;
  hpe_oneview?: HpeOneView;
  http?: Http;
  hubitat?: Hubitat;
  ibm_db2?: IbmDb2;
  influxdb?: Influxdb;
  iota?: Iota;
  ip_camera?: IpCamera;
  ip_symcon?: IpSymcon;
  ipmi?: Ipmi;
  ipp_cups?: IppCups;
  isakmp?: Isakmp;
  iscsi?: Iscsi;
  kafka?: Kafka;
  knx?: Knx;
  kubernetes?: Kubernetes;
  mpd?: Mpd;
  lantronix?: Lantronix;
  ldap?: Ldap;
  mdns?: Mdns;
  microsoft_exchange?: MicrosoftExchange;
  mikrotik_routeros?: MikrotikRouteros;
  mikrotik_winbox?: MikrotikWinbox;
  minecraft?: Minecraft;
  mitsubishi_q?: MitsubishiQ;
  monero?: Monero;
  mongodb?: Mongodb;
  msrpc?: Msrpc;
  mssql?: Mssql;
  mssql_ssrp?: MssqlSsrp;
  mqtt?: Mqtt;
  mysql?: Mysql;
  mysqlx?: Mysqlx;
  nats?: Nats;
  ndmp?: Ndmp;
  neo4j_browser?: Neo4JBrowser;
  netbios?: Netbios;
  netgear?: Netgear;
  node_exporter?: NodeExporter;
  ntlm?: Ntlm;
  ntp?: Ntp;
  openflow?: Openflow;
  openhab?: Openhab;
  openwebnet?: Openwebnet;
  oracle_tnslsnr?: OracleTnsListener;
  pcworx?: Pcworx;
  philips_hue?: PhilipsHue;
  plex?: Plex;
  pptp?: Pptp;
  qnap?: Qnap;
  rdp_encryption?: RdpEncryption;
  realport?: Realport;
  redis?: Redis;
  rip?: Rip;
  ripple?: Ripple;
  rsync?: Rsync;
  samsung_tv?: SamsungTv;
  siemens_s7?: SiemensS7;
  smb?: Smb;
  snmp?: Snmp;
  sonicwall?: Sonicwall;
  sonos?: Sonos;
  sony_bravia?: SonyBravia;
  spotify_connect?: SpotifyConnect;
  ssh?: Ssh;
  ssl?: Ssl1;
  steam_a2s?: SteamA2S;
  steam_ihs?: SteamIhs;
  stun?: Stun;
  synology?: Synology;
  synology_dsm?: Synology;
  synology_srm?: Synology;
  tacacs?: Tacacs;
  tasmota?: Tasmota;
  telnet?: Telnet;
  tibia?: Tibia;
  tilginAB_home_gateway?: TilginABHomeGateway;
  tp_link_kasa?: TpLinkKasa;
  trane_tracer_sc?: TraneTracerSc;
  ubiquiti?: Ubiquiti;
  unitronics_pcom?: UnitronicsPcom;
  upnp?: Upnp;
  vault?: Vault;
  vertx?: VertxDoor;
  vespa?: Vespa;
  vmware?: Vmware;
  vnc?: Vnc;
  windows_exporter?: WindowsExporter;
  xiaomi_miio?: XiaomiMiio;
  yeelight?: Yeelight;
}

export type Asn = string;
export type VersionMajor = number;
export type VersionMinor = number;
export type Information = string;
export type Product = string;
export type Copyright = string;
export type ExchangeExchangeBindings = boolean;
export type ConsumerCancelNotify = boolean;
export type PublisherConfirms = boolean;
export type BasicNack = boolean;
export type Platform = string;
export type Version = string;
export type Mechanisms = string;
export type Encoded = string;
export type Locales = string;
/**
 * CPE information in the old, deprecated format.
 */
export type Cpe = string[];
/**
 * CPE information in the 2.3 format.
 */
export type Cpe23 = string[];
export type Data = string;
export type Device = string;
export type Devicetype = string;
export type Domains = string[];
/**
 * Numeric hash of the "data" property which is helpful for finding other IPs with the exact same information.
 */
export type Hash = number;
/**
 * Hostnames for the IP based on the PTR/ reverse DNS information.
 */
export type Hostnames = string[];
/**
 * This property is deprecated. Use "http.html" instead.
 */
export type Html = string;
/**
 * Numeric IP address which can be more efficient for storing/ indexing.
 */
export type Ip = number;
/**
 * String representation of the IP address. This is most likely what you want to use.
 */
export type IpStr = string;
export type Info = string;
export type Ipv6 = string;
export type Isp = string;
export type Link = string;
export type Assignment = string;
export type Date = string;
export type Org = string;
/**
 * Name of the organization that manages the IP
 */
export type Org1 = string;
/**
 * Operating system
 */
export type Os = string;
export type Platform1 = string;
export type Port = number;
/**
 * Name of the software that powers the service.
 */
export type Product1 = string;
/**
 * Base64-encoded image
 */
export type Data1 = string;
/**
 * Numeric hash of the image
 */
export type Hash1 = number;
/**
 * Labels describing the image based on machine learning
 */
export type Labels = string[];
/**
 * Mimetype
 */
export type Mime = string;
/**
 * Text extracted from image using OCR
 */
export type Text = string;
/**
 * A tag is a string that can have one of the following values.
 */
export type Tag =
  | "c2"
  | "cdn"
  | "cloud"
  | "compromised"
  | "cryptocurrency"
  | "database"
  | "devops"
  | "doublepulsar"
  | "eol-os"
  | "eol-product"
  | "honeypot"
  | "ics"
  | "iot"
  | "malware"
  | "medical"
  | "onion"
  | "proxy"
  | "self-signed"
  | "scanner"
  | "ssh-bad-key"
  | "starttls"
  | "tor"
  | "videogame"
  | "vpn";
/**
 * Date and time that the banner was collected in UTC time.
 */
export type Timestamp = string;
/**
 * This property is deprecated. Use "http.title" instead.
 */
export type Title = string;
export type Transport = string;
export type Uptime = number;
export type Vendor = string;
export type Version1 = string;
export type Cvss = number;
export type References = string[];
export type Summary = string;
export type Verified = boolean;
/**
 * Deprecated
 */
export type AreaCode = string;
export type City = string;
export type CountryCode = string;
/**
 * Deprecated
 */
export type CountryCode3 = string;
export type CountryName = string;
export type DmaCode = string;
export type Latitude = number;
export type Longitude = number;
/**
 * Deprecated
 */
export type PostalCode = string;
export type RegionCode = string;
/**
 * Unique ID of the crawler
 */
export type Crawler = string;
/**
 * Unique ID of the banner; used in the "_shodan.options.referrer" to indicate when the current banner was generated as a result of another banner
 */
export type Id = string;
/**
 * The initial protocol that the crawler used when talking to the service
 */
export type Module = string;
/**
 * Hostname that was used to talk to the service (ex. for HTTP it would set the "Host:" header to this hostname)
 */
export type Hostname = string;
/**
 * Banner ID that triggered the creation of the current banner
 */
export type Referrer = string;
/**
 * Unique scan ID that identifies the request that launched the scan
 */
export type Scan = string;
/**
 * Whether or not the crawler has a PTR entry
 */
export type Ptr = boolean;
export type AfpVersions = string[];
export type DirectoryNames = string[];
export type MachineType = string;
export type NetworkAddresses = string[];
export type CopyFile = boolean;
export type FlagHex = string;
export type OpenDirectory = boolean;
export type PasswordChanging = boolean;
export type PasswordSavingProhibited = boolean;
export type Reconnect = boolean;
export type ServerMessages = boolean;
export type ServerNotifications = boolean;
export type ServerSignature = boolean;
export type SuperClient = boolean;
export type TcpIp = boolean;
export type Utf8ServerName = boolean;
export type Uuids = boolean;
export type ServerName = string;
export type ServerSignature1 = string;
export type Uams = string[];
export type Utf8ServerName1 = string;
export type AccessControlLevel = string;
export type AirplayVersion = string;
export type BluetoothAddress = string;
export type Company = string;
export type DeviceId = string;
export type DeviceModel = string;
export type FirmwareBuild = string;
export type FirmwareBuildDate = string;
export type FirmwareVersion = string;
export type HardwareRevision = string;
export type MacAddress = string;
export type Manufacturer = string;
export type Name = string;
export type OsBuildVersion = string;
export type OsVersion = string;
export type ProtocolVersion = string;
export type Sdk = string;
export type SerialNumber = string;
export type VodkaVersion = number;
export type Device1 = string;
export type Model = string;
export type Name1 = string;
export type Features = string[];
export type Appsoft = string;
export type Ip1 = string;
export type Port1 = number;
export type Ttl = number;
export type Timeout = number;
export type Bbmd = BacnetDevice[];
export type Desc = string;
export type Fdt = BacnetDevice[];
export type Firmware = string;
export type InstanceId = string;
export type Location1 = string;
export type Model1 = string;
export type Name2 = string;
export type Object = string;
export type Vendor1 = string;
export type Length = number;
export type Marker = string;
export type Type = string;
export type Asn1 = number;
export type BgpIdentifer = string;
export type HoldTime = number;
export type Version2 = number;
export type ErrorCode = string;
export type ErrorSubcode = string;
export type Messages = BgpMessage[];
export type Ip2 = string;
export type Port2 = number;
export type Addresses = BitcoinPeer[];
export type Checksum = string;
export type Command = string;
export type Ipv4 = string;
export type Ipv61 = string;
export type Port3 = number;
export type Services = number;
export type Timestamp1 = number;
export type Lastblock = number;
export type Length1 = number;
export type MagicNumber = string;
export type Nonce = number;
export type Relay = boolean;
export type Services1 = number;
export type Timestamp2 = number;
export type UserAgent = string;
export type Version3 = number;
export type Handshake = BitcoinMessage[];
export type Name3 = string;
export type Keyspaces = string[];
export type Partitioner = string;
export type Snitch = string;
export type Version4 = string;
export type ThriftApiVersion = string;
export type FirewallHost = string;
export type SmartcenterHost = string;
export type BuildType = number;
export type CastBuildRevision = string;
export type CastControlVersion = number;
export type ReleaseTrack = string;
export type SystemBuildNumber = string;
export type CloudDeviceId = string;
export type DeviceName = string;
export type HotspotBssid = string;
export type MacAddress1 = string;
export type Manufacturer1 = string;
export type ModelName = string;
export type ProductName = string;
export type PublicKey = string;
export type SsdpUdn = string;
export type UmaClientId = string;
export type EthernetConnected = boolean;
export type IpAddress = string;
export type Online = boolean;
export type Version5 = number;
export type Ssid = string;
export type Bssid = string;
export type ConfigHash = string;
export type GroupAlias = string;
export type TunnelGroup = string;
export type Version6 = string;
export type PrimaryStatus = string;
export type ReplicasStatus = string;
export type RequiredLogin = boolean;
export type ServerName1 = string;
export type Version7 = string;
export type Provider = string;
export type Region = string;
export type Service = string;
export type BeaconType = string;
export type DnsBeaconStrategyFailSeconds = number;
export type DnsBeaconStrategyFailX = number;
export type DnsBeaconStrategyRotateSeconds = number;
export type HttpGetClient = string[];
export type HttpGetUri = string;
export type HttpGetVerb = string;
export type HttpPostClient = string[];
export type HttpPostUri = string;
export type HttpPostVerb = string;
export type Jitter = number;
export type KillDate = number;
export type Maxgetsize = number;
export type Port4 = number;
export type PostExSpawntoX64 = string;
export type PostExSpawntoX86 = string;
export type ProcessInjectExecute = string[];
export type ProcessInjectMinAlloc = number;
export type ProcessInjectStartrwx = number;
export type ProcessInjectUserwx = number;
export type ProxyBehavior = number | string;
export type Sleeptime = number;
export type StageCleanup = number;
export type UseragentHeader = string;
export type Watermark = number;
export type ExperimentalUserLogin = boolean;
export type NodeId = string;
export type OidcLoginEnable = boolean;
export type Tag1 = string;
export type Version8 = string;
export type Product2 = string;
export type Os1 = string;
export type OsDetails = string;
export type Datacenter = string;
export type Nodeid = string;
export type Nodename = string;
export type Primarydatacenter = string;
export type Revision = string;
export type Server = boolean;
export type Version9 = string;
export type Implementationversion = string;
export type Couchdb = string;
export type Version10 = string;
export type PersistentConfig = boolean;
export type Couchdb2 = string;
export type Features1 = string[];
export type GitSha = string;
export type HttpHeaders = string;
export type Uuid = string;
export type Version11 = string;
export type SerialNumber1 = string;
export type ChannelNames = string[];
export type Classid = string;
export type MacVersion = string;
export type Name4 = string;
export type Version12 = string;
export type UserInfo = string;
export type WebVersion = string;
export type AllowedMethods = string[];
export type Ips = string[];
export type Paths = string[];
export type PublicOptions = string[];
export type ServerDate = string;
export type ServerType = string;
export type WebdavType = string;
export type Recursive = boolean;
export type ResolverHostname = string;
export type ResolverId = string;
export type Software = string;
export type Apiversion = string;
export type Arch = string;
export type Buildtime = string;
export type Gitcommit = string;
export type Goversion = string;
export type Kernelversion = string;
export type Minapiversion = string;
export type Os2 = string;
export type Version13 = string;
export type Error = string;
export type Repositories = string[];
export type BuildTime = string;
export type DzeventsVersion = string;
export type Hash2 = string;
export type PythonVersion = string;
export type Version14 = string;
export type BuildTime1 = string;
export type Api = string;
export type Clienturls = string[];
export type Dbsize = number;
export type Id1 = number | string;
export type Name5 = string;
export type Peerurls = string[];
export type Recvappendrequestcnt = number;
export type Recvbandwidthrate = number;
export type Recvpkgrate = number;
export type Sendappendrequestcnt = number;
export type Sendbandwidthrate = number;
export type Sendpkgrate = number;
export type Starttime = string;
export type State = string;
export type Version15 = string;
export type Pubkey = string;
export type Version16 = number;
export type TcpPort = number;
export type UdpPort = number;
export type Ip3 = string;
export type Pubkey1 = string;
export type TcpPort1 = number;
export type UdpPort1 = number;
export type Neighbors = EthereumP2PNeighbour[];
export type Client = string;
export type Version17 = string;
export type Platform2 = string;
export type Compiler = string;
export type Hashrate = string;
export type ChainId = string;
export type Accounts = string[];
export type Command1 = number;
export type CommandLength = number;
export type CommandStatus = number;
export type DeviceType = string;
export type EncapsulationLength = number;
export type Ip4 = string;
export type ItemCount = number;
export type Options = number;
export type ProductCode = number;
export type ProductName1 = string;
export type ProductNameLength = number;
export type Raw = string;
export type RevisionMajor = number;
export type RevisionMinor = number;
export type SenderContext = string;
export type Serial = number;
export type Session = number;
export type SocketAddr = string;
export type State1 = number;
export type Status = number;
export type TypeId = number;
export type VendorId = string;
export type Version18 = number;
export type Device2 = string;
export type SerialNumber2 = string;
export type Model2 = string;
export type Anonymous = boolean;
export type Parameters = string[];
export type FeaturesHash = number;
export type Owner = string;
export type Hosts = {
  [k: string]: string;
}[];
export type Name6 = string;
export type Clusters = GangliaCluster[];
export type Version19 = string;
export type AdapterType = string;
export type EpromVersion = string;
export type MaxLogs = number;
export type MaxUsers = number;
export type MemorySize = string;
export type Model3 = string;
export type ModelName1 = string;
export type SerialNumber3 = number;
export type TotalLogs = number;
export type TotalUsers = number;
export type ClusterKey = string;
export type Coprocessors = string;
export type HadoopCompiled = string;
export type HadoopSourceChecksum = string;
export type HadoopVersion = string;
export type HbaseClusterId = string;
export type HbaseCompiled = string;
export type HbaseSourceChecksum = string;
export type HbaseRootDirectory = string;
export type HbaseVersion = string;
export type HmasterActiveTime = string;
export type HmasterStartTime = string;
export type JvmVersion = string;
export type LoadAverage = string;
export type Loadbalancer = string;
export type RestServerStartTime = string;
export type ZookeeperBasePath = string;
export type ZookeeperClientCompiled = string;
export type ZookeeperClientVersion = string;
export type ZookeeperQuorum = string;
export type HbaseMaster = string;
export type RsStartTime = string;
export type CustomVersion = string;
export type CustomVersion2 = string;
export type DeviceDescription = string;
export type DeviceModel1 = string;
export type DeviceName1 = string;
export type DeviceVersion = string;
export type PluginVersion = string;
export type WebVersion1 = string;
export type Name7 = string;
export type Properties = {
  [k: string]: string;
}[];
export type Tables = ApacheHiveTable[];
export type Databases = ApacheHiveDatabase[];
export type BaseUrl = string;
export type ExternalUrl = string;
export type LocationName = string;
export type InstallationType = string;
export type InternalUrl = string;
export type Uuid1 = string;
export type Version20 = string;
export type EnableTerminalAccess = boolean;
export type EnableAccessories = boolean;
export type InstanceId1 = string;
export type InstanceName = string;
export type NodeVersion = string;
export type Platform3 = string;
export type RunningInDocker = boolean;
export type RunningInLinux = boolean;
export type ServiceMode = boolean;
export type UiPackageName = string;
export type UiPackageVersion = string;
export type Name8 = string;
export type Pin = string;
export type Port5 = number;
export type Username = string;
export type CountryCode1 = string;
export type PostalCode1 = string;
export type ApplicationPath = string;
export type ConfigurationPath = string;
export type GlobalModulesPath = string;
export type HomeSetupId = string;
export type HoobsVersion = string;
export type LocalModulesPath = string;
export type NodeVersion1 = string;
export type Port6 = number;
export type Cuuid = string;
export type IloFirmware = string;
export type IloSerialNumber = string;
export type IloType = string;
export type IloUuid = string;
export type Description = string;
export type IpAddress1 = string;
export type Location2 = string;
export type MacAddress2 = string;
export type Port7 = string;
export type Status1 = string;
export type Nics = HpIloNic[];
export type ProductId = string;
export type SerialNumber4 = string;
export type ServerType1 = string;
export type Uuid2 = string;
export type MinimumVersion = string;
export type CurrentVersion = string;
export type Categories = string[];
/**
 * Favicon for the website. Helpful to find phishing websites, fingerprinting products or locating websites from the same vendor/ company.
 */
export type Favicon = HttpFavicon;
export type Data2 = string;
export type Hash3 = number;
export type Location3 = string;
/**
 * Numeric hash of the HTTP headers with the order preserved.
 */
export type HeadersHash = number;
export type Host = string;
export type Html1 = string;
/**
 * Numeric hash of the "http.html" property. Useful for finding other IPs with the exact same website.
 */
export type HtmlHash = number;
export type Location4 = string;
export type Data3 = string;
export type Host1 = string;
export type Location5 = string;
export type Redirects = HttpRedirect[];
/**
 * Contents of the robots.txt file.
 */
export type Robots = string;
/**
 * Numeric hash of the robots.txt file which can be used to find websites that have the same robots.txt.
 */
export type RobotsHash = number;
/**
 * The security.txt file is an emerging standard for knowing how to contact the website owner for security issues.
 */
export type Securitytxt = string;
export type SecuritytxtHash = number;
/**
 * Short-hand for accessing the value from the "Server" HTTP header.
 */
export type Server1 = string;
export type Sitemap = string;
export type SitemapHash = number;
export type Status2 = number;
export type Title1 = string;
/**
 * Web application firewall that is protecting this website.
 */
export type Waf = string;
export type HardwareVersion = string;
export type HubUid = string;
export type IpAddress2 = string;
export type MacAddress3 = string;
export type Version21 = string;
export type Db2Version = string;
export type InstanceName1 = string;
export type ServerPlatform = string;
export type ExternalName = string;
export type BindAddress = string;
export type Build = string;
export type Databases1 = string[];
export type GoArch = string;
export type GoMaxProcs = number;
export type GoOs = string;
export type GoVersion = string;
export type NetworkHostname = string;
export type Uptime1 = string;
export type Version22 = string;
export type AliasName = string;
export type AppVersion = string;
export type Brand = string;
export type Build1 = string;
export type ClientVersion = string;
export type DdnsHost = string;
export type HardwareVersion1 = string;
export type Id2 = string;
export type IpAddress3 = string;
export type MacAddress4 = string;
export type Model4 = string;
export type Name9 = string;
export type Product3 = string;
export type ServerVersion = string;
export type SoftwareVersion = string;
export type SystemVersion = string;
export type Version23 = string;
export type ApiVersion = string;
export type Name10 = string;
export type Password = boolean;
export type Houses = IpSymconHouse[];
export type Version24 = string;
export type UserAuth = string[];
export type Version25 = string;
export type PasswordAuth = string[];
export type Level = string[];
export type Oemid = number;
export type AuthenticationType = string;
export type DnsSdName = string;
export type Info1 = string;
export type MakeAndModel = string;
export type Name11 = string;
export type UriSupported = string;
export type Printers = IppCupsPrinter[];
export type StatusMessage = string;
export type ExchangeType = number;
export type Authentication = boolean;
export type Commit = boolean;
export type Encryption = boolean;
export type InitiatorSpi = string;
export type Length2 = number;
export type MsgId = string;
export type NextPayload = number;
export type ResponderSpi = string;
export type VendorIds = string[];
export type Version26 = string;
export type Addresses1 = string[];
export type AuthEnabled = boolean;
export type AuthError = string;
export type Name12 = string;
export type Targets = IscsiTarget[];
export type Id3 = string;
export type Name13 = string;
export type Port8 = number;
export type Rack = string;
export type Brokers = KafkaBroker[];
export type Name14 = string;
export type Port9 = number;
export type Hosts1 = KafkaHost[];
export type Topics = string[];
export type FriendlyName = string;
export type KnxAddress = string;
export type Mac1 = string;
export type MulticastAddress = string;
export type Serial1 = string;
export type Core = string;
export type DeviceManagement = string;
export type Routing = string;
export type Tunneling = string;
export type BuildDate = string;
export type GoVersion1 = string;
export type Name15 = string;
export type Image = string;
export type Name16 = string;
export type Containers = KubernetesContainer[];
export type Nodes2 = KubernetesNode[];
export type Platform4 = string;
export type Version27 = string;
export type Uptime2 = string;
export type DbUpdate = string;
export type Suffix = string[];
export type Artists = string;
export type Plugin = string[];
export type Playtime = string;
export type Albums = string;
export type Songs = string;
export type MimeType = string[];
export type DbPlaytime = string;
export type Gateway = string;
export type Ip5 = string;
export type Mac2 = string;
export type Password1 = string;
export type Type1 = string;
export type Version28 = string;
export type Configurationnamingcontext = string | string[];
export type Currenttime = string | string[];
export type Currenttime1 = string | string[];
export type Defaultnamingcontext = string | string[];
export type Dnshostname = string | string[];
export type Domainfunctionality = string | string[];
export type Dsservicename = string | string[];
export type Forestfunctionality = string | string[];
export type Highestcommittedusn = string | string[];
export type Isglobalcatalogready = string | string[];
export type Issynchronized = string | string[];
export type Ldapservicename = string | string[];
export type Rootdomainnamingcontext = string | string[];
export type Schemanamingcontext = string | string[];
export type Servername = string | string[];
export type Supportedcapabilities = string | string[];
export type Supportedldappolicies = string | string[];
export type Errormessage = string;
export type Namingcontexts = string | string[];
export type Resultcode = string;
export type Subschemasubentry = string | string[];
export type Subschemasubentry1 = string | string[];
export type Supportedcontrol = string | string[];
export type Supportedextension = string | string[];
export type Supportedldapversion = string | string[];
export type Supportedldapversion1 = string | string[];
export type Supportedldapversion2 = string | string[];
export type Supportedsaslmechanisms = string | string[];
export type Namingcontexts1 = string | string[];
export type Subschemasubentry2 = string | string[];
export type Supportedcontrol1 = string | string[];
export type Supportedextension1 = string | string[];
export type Supportedldapversion3 = string | string[];
export type Supportedsaslmechanisms1 = string | string[];
export type Dnshostname1 = string | string[];
export type Altserver = string | string[];
export type Objectclass = string | string[];
export type Domaincontrollerfunctionality = string | string[];
export type Ipv41 = string[];
export type Ipv62 = string[];
export type Name17 = string;
export type Port10 = number;
export type Ptr1 = string;
export type BuildDate1 = string;
export type BuildNumber = string;
export type Name18 = string;
export type Interfaces = string[];
export type Version29 = string;
export type Crc = number;
export type Size = number;
export type Version30 = string;
export type Brand1 = string;
export type Description1 = string | string[] | MinecraftDescription;
export type Extra = (MinecraftDescription | string)[];
export type Text1 = string;
export type Translate = string;
export type Enforcessecurechat = boolean;
export type Favicon1 = string;
export type Gamemode = string;
export type Lcserver = string;
export type Map = string;
export type Max = number;
export type Online1 = number;
export type Id4 = string;
export type Name19 = string;
export type Sample = MinecraftPlayer[];
export type Preventschatreports = boolean;
export type Previewschat = boolean;
export type Translate1 = string;
export type Name20 = string;
export type Protocol = number;
export type With = string[];
export type Cpu = string;
export type Authentication1 = boolean;
export type ActualCount = number;
export type MaxCount = number;
export type NumTowers = number;
export type Annotation = string;
export type Bindings = {
  [k: string]: string;
}[];
export type Version31 = string;
export type DnsComputerName = string;
export type DnsDomainName = string;
export type NetbiosComputerName = string;
export type NetbiosDomainName = string;
export type OsVersion1 = string;
export type TargetRealm = string;
export type Timestamp3 = number;
export type InstanceName2 = string;
export type IsClustered = boolean;
export type ServerName2 = string;
export type Tcp = number;
export type Version32 = string;
export type VersionName = string;
export type Instances = MssqlSsrpInstance[];
export type Code = number;
export type Payload = string;
export type Topic = string;
export type Messages1 = MqttMessage[];
export type AuthenticationPlugin = string;
export type Capabilities = number;
export type ErrorCode1 = number;
export type ErrorMessage = string;
export type ExtendedServerCapabilities = number;
export type ProtocolVersion1 = number;
export type ServerLanguage = number;
export type ServerStatus = number | string;
export type ThreadId = number;
export type Version33 = string;
export type Tls = boolean;
export type ClientPwdExpireOk = boolean;
export type Algorithm = string[];
export type DocFormats = string;
export type NodeType = string;
export type ClientInteractive = boolean;
export type AuthenticationMechanisms = string[];
export type AuthRequired = boolean;
export type ClientId = number;
export type ClientIp = string;
export type Cluster1 = string;
export type ConnectionId = string;
export type GitCommit = string;
export type Go = string;
export type Headers = boolean;
export type Host2 = string;
export type Jetstream = boolean;
export type Lnoc = boolean;
export type MaxPayload = number;
export type Nonce1 = string;
export type Port11 = number;
export type Proto = number;
export type ServerId = string;
export type ServerName3 = string;
export type TlsRequired = boolean;
export type TlsVerify = boolean;
export type Version34 = string;
export type ConnectUrls = string[];
export type Ip6 = string;
export type LeafnodeUrls = string[];
export type Xkey = string;
export type FsLogicalDevice = string;
export type FsPhysicalDevice = string;
export type FsType = string;
export type Devices = NdmpDevice[];
export type BuildNumber1 = string;
export type BuiltAt = string;
export type Version35 = string;
export type Mac3 = string;
export type Flags = number;
export type Name21 = string;
export type Suffix1 = number;
export type Names = NetbiosShare[];
export type Networks = string[];
export type Raw1 = string[];
export type ServerName4 = string;
export type Username1 = string;
export type Description2 = string;
export type FirewallVersion = string;
export type FirmwareVersion1 = string;
export type FirstUseDate = string;
export type ModelName2 = string;
export type SerialNumber5 = string;
export type SmartagentVersion = string;
export type VpnVersion = string;
export type Branch = string;
export type Goversion1 = string;
export type Revision1 = string;
export type Version36 = string;
export type Domainname = string;
export type Machine = string;
export type Nodename1 = string;
export type Release = string;
export type Sysname = string;
export type Version37 = string;
export type Name22 = string;
export type PrettyName = string;
export type IdLike = string;
export type VersionId = string;
export type VersionCodename = string;
export type Version38 = string;
export type Id5 = string;
export type ChassisVersion = string;
export type BiosVendor = string;
export type ProductVersion = string;
export type SystemVendor = string;
export type BiosRelease = string;
export type BiosDate = string;
export type BiosVersion = string;
export type ChassisVendor = string;
export type ProductName2 = string;
export type ProductFamily = string;
export type Broadcast = string;
export type Device3 = string;
export type Operstate = string;
export type Address = string;
export type Duplex = string;
export type Device4 = string;
export type FirmwareRevision = string;
export type Model5 = string;
export type Serial2 = string;
export type State2 = string;
export type BoardId = string;
export type Device5 = string;
export type FirmwareVersion2 = string;
export type HcaType = string;
export type DnsDomainName1 = string;
export type DnsForestName = string;
export type Fqdn = string;
export type NetbiosComputerName1 = string;
export type NetbiosDomainName1 = string;
export type Os3 = string[];
export type OsBuild = string;
export type TargetRealm1 = string;
export type Timestamp4 = number;
export type ClkJitter = number | string;
export type ClkWander = number | string;
export type Clock = string;
export type ClockOffset = number;
export type Delay = number;
export type Frequency = number | string;
export type Jitter1 = number | string;
export type Leap = number | string;
export type Mintc = number;
export type Connections = string[];
export type More = boolean;
export type Noise = number | string;
export type Offset = number | string;
export type Peer = number | string;
export type Phase = number | string;
export type Poll = number | string;
export type Precision = number;
export type Processor = string;
export type Refid = string;
export type Reftime = string;
export type RootDelay = number | string;
export type RootDispersion = number | string;
export type Rootdelay = number | string;
export type Rootdisp = number | string;
export type Stability = number | string;
export type State3 = number;
export type Stratum = number;
export type SysJitter = number | string;
export type System = string;
export type Tai = number | string;
export type Tc = number;
export type Version39 = string;
export type SupportedVersions = string | string[];
export type Version40 = string;
export type Build2 = string;
export type Version41 = string;
export type DateAndTime = string;
export type DeviceType1 = string;
export type DistributionVersion = string;
export type FirmwareVersion3 = string;
export type IpAddress4 = string;
export type KernelVersion = string;
export type MacAddress5 = string;
export type NetMask = string;
export type Automation = number;
export type BurglarAlarm = number;
export type Heating = number;
export type Lighting = number;
export type PowerManagement = number;
export type Uptime3 = string;
export type Err = number;
export type Vsnnum = number;
export type FirmwareDate = string;
export type FirmwareTime = string;
export type FirmwareVersion4 = string;
export type ModelNumber = string;
export type PlcType = string;
export type ApiVersion1 = string;
export type BridgeId = string;
export type DataStoreVersion = string;
export type FactoryNew = boolean;
export type Mac4 = string;
export type ModelId = string;
export type Name23 = string;
export type SwVersion = string;
export type MachineIdentifier = string;
export type Version42 = string;
export type Firmware1 = string;
export type Hostname1 = string;
export type Vendor4 = string;
export type Build3 = string;
export type Checksum1 = string;
export type Version43 = string;
export type Build4 = string;
export type Number = string;
export type Patch = string;
export type Version44 = string;
export type Hostname2 = string;
export type CustomModelName = string;
export type DisplayModelName = string;
export type InternalModelName = string;
export type ModelName3 = string;
export type Platform5 = string;
export type PlatformEx = string;
export type ProjectName = string;
export type Levels = string[];
export type Methods = string[];
export type Protocols = string[];
export type Name24 = string;
export type Ports = number;
export type Clients =
  | {
      [k: string]: unknown;
    }[]
  | {
      [k: string]: unknown;
    };
export type Cluster2 =
  | {
      [k: string]: unknown;
    }
  | string[];
export type Data4 = string[];
export type More1 = boolean;
export type Addr = string;
export type Family = string;
export type Metric = number;
export type NextHop = string;
export type Subnet = string;
export type Tag2 = number;
export type Addresses2 = RipAddress[];
export type Password2 = string;
export type Type2 = number;
export type Command2 = number;
export type Version45 = number;
export type CompleteLedgers = string;
export type Ip7 = string;
export type Port12 = string;
export type PublicKey1 = string;
export type Type3 = string;
export type Uptime4 = number;
export type Version46 = string;
export type Peers = RipplePeer[];
export type Authentication2 = boolean;
export type DeviceId1 = string;
export type DeviceName2 = string;
export type Model6 = string;
export type ModelDescription = string;
export type ModelName4 = string;
export type MsfVersion = string;
export type Ssid1 = string;
export type WifiMac = string;
export type DstTsap = string;
export type Raw2 = string;
export type Value = string;
export type SrcTsap = string;
export type Anonymous1 = boolean;
export type Capabilities1 = string[];
export type Os4 = string;
export type Raw3 = string[];
export type Comments = string;
export type Directory = boolean;
export type Name25 = string;
export type ReadOnly = boolean;
export type Size1 = number;
export type Files = SmbFile[];
export type Name26 = string;
export type Special = boolean;
export type Temporary = boolean;
export type Type4 = string;
export type Shares = SmbItem[];
export type Software1 = string;
export type SmbVersion = number;
export type Contact = string;
export type Description3 = string;
export type Location6 = string;
export type Name27 = string;
export type Objectid = string;
export type Ordescr = string;
export type Orid = string;
export type Orindex = string;
export type Orlastchange = string;
export type Oruptime = string;
export type Uptime5 = string;
export type Services3 = string;
export type SonicosVersion = string;
export type SerialNumber6 = string;
export type FriendlyName1 = string;
export type HardwareVersion2 = string;
export type MacAddress6 = string;
export type ModelName5 = string;
export type Raw4 = string;
export type RoomName = string;
export type SerialNumber7 = string;
export type SoftwareVersion1 = string;
export type Udn = string;
export type InterfaceVersion = string;
export type ModelName6 = string;
export type MacAddress7 = string;
export type ActiveUser = string;
export type BrandDisplayName = string;
export type ClientId1 = string;
export type DeviceId2 = string;
export type DeviceType2 = string;
export type LibraryVersion = string;
export type ModelDisplayName = string;
export type RemoteName = string;
export type PublicKey2 = string;
export type Scope = string;
export type Version47 = string;
export type Cipher = string;
export type Fingerprint = string;
export type Hassh = string;
export type CompressionAlgorithms = string[];
export type EncryptionAlgorithms = string[];
export type KexAlgorithms = string[];
export type KexFollows = boolean;
export type Languages = string[];
export type MacAlgorithms = string[];
export type ServerHostKeyAlgorithms = string[];
export type Unused = number;
export type Key = string;
export type Mac5 = string;
export type Type5 = string;
export type Hash4 = number;
export type Raw5 = string;
export type AcceptableCas = SslCas[];
export type Alpn = string[];
export type Expired = boolean;
export type Expires = string;
export type Critical = boolean;
export type Data5 = string;
export type Name28 = string;
export type Extensions = SslCertificateExtension[];
export type Sha1 = string;
export type Sha256 = string;
export type Issued = string;
export type Serial3 = number;
export type SigAlg = string;
export type Version48 = number;
/**
 * List of certificates in PEM format
 */
export type Chain = string[];
export type ChainSha256 = string[];
/**
 * Default cipher used for the connection
 */
export type Cipher1 = SslCipher;
export type Bits = number;
export type Name29 = string;
export type Version49 = string;
export type Bits1 = number;
export type Fingerprint1 = string;
export type Generator = number | string;
export type Prime = string;
export type PublicKey3 = string;
/**
 * Detailed breakdown of how the SSL/TLS connection was negotiated.
 */
export type HandshakeStates = string[];
/**
 * JA3 fingerprint for the server SSL/TLS connection. Useful for pivoting or identifying SSL/TLS implementations.
 */
export type Ja3S = string;
/**
 * JARM fingerprint for the server SSL/TLS connection. Useful for pivoting or identifying SSL/TLS implementations.
 */
export type Jarm = string;
export type Ocsp =
  | SslOcsp
  | {
      [k: string]: unknown;
    };
export type HashAlgorithm = string;
export type IssuerNameHash = string;
export type IssuerNameKey = string;
export type SerialNumber8 = string;
export type CertStatus = string;
export type NextUpdate = string;
export type ProducedAt = string;
export type ResponderId = string;
export type ResponseStatus = string;
export type SignatureAlgorithm = string;
export type ThisUpdate = string;
export type Version50 = string;
export type Id6 = string;
export type Name30 = string;
export type Tlsext = SslExtension[];
export type Apple = boolean;
export type Microsoft = boolean;
export type Mozilla = boolean;
export type Revoked =
  | boolean
  | {
      [k: string]: boolean;
    };
/**
 * If the crawlers couldn't gather a property (ex. "versions") due to an unstable connection then the name of that property is added here.
 */
export type Unstable = string[];
/**
 * The crawlers explicitly check every SSL/TLS version. If the server doesn't support a version then a "-" is in front of the version value.
 */
export type Versions1 = string[];
export type Address1 = string;
export type AppId = number;
export type ClientDll = number;
export type GamePort = number;
export type IsMod = number;
export type Map1 = string;
export type ModSize = number;
export type ModVersion = number;
export type Name31 = string;
export type Protocol1 = number;
export type ServerType2 = string;
export type Folder = string;
export type Players = number;
export type Game = string;
export type Version51 = string;
export type MaxPlayers = number;
export type Password3 = number;
export type Os5 = string;
export type Bots = number;
export type Secure = number;
export type ServerOnly = number;
export type SpecPort = number;
export type SpecName = string;
export type SteamId = number;
export type Tags = string;
export type UrlDownload = string;
export type UrlInfo = string;
export type Visibility = number;
export type ClientId2 = string;
export type ConnectPort = number;
export type EnabledServices = number;
export type Euniverse = number;
export type Hostname3 = string;
export type InstanceId2 = string;
export type IpAddresses = string[];
export type Is64Bit = boolean;
export type MacAddresses = string[];
export type MinVersion = number;
export type OsType = number;
export type PublicIpAddress = string;
export type Timestamp5 = number;
export type AuthKeyId = number;
export type SteamId1 = string;
export type Users = SteamIhsUser[];
export type Version52 = number;
export type ServerIp = string;
export type Software2 = string;
export type Hostname4 = string;
export type CustomLoginTitle = string;
export type LoginWelcomeTitle = string;
export type LoginWelcomeMsg = string;
export type Version53 = string;
export type Flags1 = number;
export type Length3 = number;
export type Sequence = number;
export type Session1 = number;
export type Type6 = number;
export type Version54 = string;
export type BuildDate2 = string;
export type Core1 = string;
export type Sdk1 = string;
export type Version55 = string;
export type FriendlyNames = string | string[];
export type Module1 = string;
export type Hostname5 = string;
export type IpAddress5 = string;
export type MacAddress8 = string;
export type Bssid1 = string;
export type Ssid2 = string;
export type Do = string[];
export type Dont = string[];
export type Will = string[];
export type Wont = string[];
export type ProductName3 = string;
export type SoftwareFamily = string;
export type SoftwareRevision = string;
export type Alias = string;
export type DevName = string;
export type DeviceId3 = string;
export type FwId = string;
export type HwId = string;
export type HwVer = string;
export type Latitude1 = number;
export type Longitude1 = number;
export type MacAddress9 = string;
export type Model7 = string;
export type OemId = string;
export type SwVer = string;
export type Type7 = string;
export type DeviceName3 = string;
export type DisplayName = string;
export type EquipmentFamily = string;
export type EquipmentUri = string;
export type IsOffline = boolean;
export type RoleDocument = string;
export type Equipments = TraneTracerScEquipment[];
export type HardwareSerialNumber = string;
export type HardwareType = string;
export type KernelVersion1 = string;
export type ProductName4 = string;
export type ProductVersion1 = string;
export type ServerBootTime = string;
export type ServerName5 = string;
export type ServerTime = string;
export type VendorName = string;
export type Hostname6 = string;
export type Ip8 = string;
export type IpAlt = string;
export type Mac6 = string;
export type MacAlt = string;
export type Product4 = string;
export type Version56 = string;
export type HardwareVersion3 = string;
export type Model8 = string;
export type OsBuild1 = number;
export type OsVersion2 = number;
export type PlcName = string;
export type PlcUniqueId = number;
export type UidMaster = number;
export type DeviceType3 = string;
export type FriendlyName2 = string;
export type Manufacturer2 = string;
export type ManufacturerUrl = string;
export type ModelDescription1 = string;
export type ModelName7 = string;
export type ModelNumber1 = string;
export type ModelUrl = string;
export type PresentationUrl = string;
export type SerialNumber9 = string;
export type ControlUrl = string;
export type EventSubUrl = string;
export type Scpdurl = string;
export type ServiceId = string;
export type ServiceType = string;
export type Services4 = UpnpService[];
export type SubDevices = Upnp[];
export type Udn1 = string;
export type Upc = string;
export type ClusterId = string;
export type ClusterName = string;
export type Initialized = boolean;
export type PerformanceStandby = boolean;
export type ReplicationDrMode = string;
export type ReplicationPerformanceMode = string;
export type Sealed = boolean;
export type ServerTimeUtc = number;
export type Standby = boolean;
export type Version57 = string;
export type LastWal = string;
export type Terminated = boolean;
export type State4 = string;
export type ExpiryTime = string;
export type FirmwareDate1 = string;
export type FirmwareVersion5 = string;
export type InternalIp = string;
export type Mac7 = string;
export type Name32 = string;
export type Type8 = string;
export type Name33 = string;
export type Generation = number;
export type Timestamp6 = number;
export type User = string;
export type Checksum2 = string;
export type Date1 = string;
export type Path = string;
export type Id7 = string;
export type Bundle = string;
export type Class = string;
export type Servers = VespaServer[];
export type ApiType = string;
export type ApiVersion2 = string;
export type Build5 = string;
export type FullName = string;
export type InstanceUuid = string;
export type LicenseProductName = string;
export type LicenseProductVersion = string;
export type LocaleBuild = string;
export type LocaleVersion = string;
export type Name34 = string;
export type OsType1 = string;
export type ProductLineId = string;
export type Vendor5 = string;
export type Version58 = string;
export type Geometry = string;
export type ProtocolVersion2 = string;
export type ServerName6 = string;
export type DeviceId4 = string;
export type Token = string;
export type FirmwareVersion6 = string;
export type Model9 = string;

export interface Amqp {
  version_major?: VersionMajor;
  version_minor?: VersionMinor;
  server_properties?: AmqpServerProperties;
  mechanisms?: Mechanisms;
  encoded?: Encoded;
  locales?: Locales;
  [k: string]: unknown;
}
export interface AmqpServerProperties {
  information?: Information;
  product?: Product;
  copyright?: Copyright;
  capabilities?: AmqpCapabilities;
  platform?: Platform;
  version?: Version;
  [k: string]: unknown;
}
export interface AmqpCapabilities {
  exchange_exchange_bindings: ExchangeExchangeBindings;
  consumer_cancel_notify: ConsumerCancelNotify;
  publisher_confirms: PublisherConfirms;
  "basic.nack": BasicNack;
  [k: string]: unknown;
}
export interface Mac {
  [k: string]: MacAddressInfo;
}
export interface MacAddressInfo {
  assignment: Assignment;
  date?: Date;
  org: Org;
  [k: string]: unknown;
}
/**
 * Stores experimental data before it has been finalized into a top-level property.
 */
export interface Opts {
  [k: string]: unknown;
}
export interface Screenshot {
  data: Data1;
  hash: Hash1;
  labels?: Labels;
  mime: Mime;
  text?: Text;
}
export interface Vulns {
  [k: string]: Vulnerability;
}
export interface Vulnerability {
  cvss?: Cvss;
  references: References;
  summary: Summary;
  verified: Verified;
  [k: string]: unknown;
}
/**
 * Physical location based on the IP address. Generally accurate to the city level. Don't consider the latitude/ longitude as accurate but rather rough location.
 */
export interface Location {
  area_code?: AreaCode;
  city?: City;
  country_code?: CountryCode;
  country_code3?: CountryCode3;
  country_name?: CountryName;
  dma_code?: DmaCode;
  latitude?: Latitude;
  longitude?: Longitude;
  postal_code?: PostalCode;
  region_code?: RegionCode;
  [k: string]: unknown;
}
/**
 * The _shodan property contains information about how the banner was generated. It doesn't store any data about the port/ service itself.
 */
export interface _Shodan {
  crawler: Crawler;
  id: Id;
  module: Module;
  options: _ShodanOptions;
  ptr?: Ptr;
  [k: string]: unknown;
}
export interface _ShodanOptions {
  hostname?: Hostname;
  referrer?: Referrer;
  scan?: Scan;
  [k: string]: unknown;
}
/**
 * The Apple File Protocol (AFP) is used by Apple devices to share files across the network.
 */
export interface Afp {
  afp_versions: AfpVersions;
  directory_names?: DirectoryNames;
  machine_type: MachineType;
  network_addresses?: NetworkAddresses;
  server_flags: AfpFlags;
  server_name: ServerName;
  server_signature?: ServerSignature1;
  uams: Uams;
  utf8_server_name?: Utf8ServerName1;
}
export interface AfpFlags {
  copy_file: CopyFile;
  flag_hex: FlagHex;
  open_directory: OpenDirectory;
  password_changing: PasswordChanging;
  password_saving_prohibited: PasswordSavingProhibited;
  reconnect: Reconnect;
  server_messages: ServerMessages;
  server_notifications: ServerNotifications;
  server_signature: ServerSignature;
  super_client: SuperClient;
  tcp_ip: TcpIp;
  utf8_server_name: Utf8ServerName;
  uuids: Uuids;
  [k: string]: unknown;
}
export interface Airplay {
  access_control_level?: AccessControlLevel;
  airplay_version?: AirplayVersion;
  bluetooth_address?: BluetoothAddress;
  company?: Company;
  device_id?: DeviceId;
  device_model?: DeviceModel;
  firmware_build?: FirmwareBuild;
  firmware_build_date?: FirmwareBuildDate;
  firmware_version?: FirmwareVersion;
  hardware_revision?: HardwareRevision;
  mac_address?: MacAddress;
  manufacturer?: Manufacturer;
  name?: Name;
  os_build_version?: OsBuildVersion;
  os_version?: OsVersion;
  protocol_version?: ProtocolVersion;
  sdk?: Sdk;
  serial_number?: SerialNumber;
  vodka_version?: VodkaVersion;
  [k: string]: unknown;
}
export interface AndroidDebugBridge {
  device: Device1;
  model: Model;
  name: Name1;
  features?: Features;
}
export interface Bacnet {
  appsoft?: Appsoft;
  bbmd: Bbmd;
  desc?: Desc;
  fdt: Fdt;
  firmware?: Firmware;
  instance_id?: InstanceId;
  location?: Location1;
  model?: Model1;
  name?: Name2;
  object?: Object;
  vendor?: Vendor1;
}
export interface BacnetDevice {
  ip: Ip1;
  port: Port1;
  ttl?: Ttl;
  timeout?: Timeout;
  [k: string]: unknown;
}
/**
 * BGP services that respond to a peering request
 */
export interface Bgp {
  messages: Messages;
}
export interface BgpMessage {
  length: Length;
  marker?: Marker;
  type: Type;
  asn?: Asn1;
  bgp_identifer?: BgpIdentifer;
  hold_time?: HoldTime;
  version?: Version2;
  error_code?: ErrorCode;
  error_subcode?: ErrorSubcode;
  [k: string]: unknown;
}
export interface Bitcoin {
  addresses: Addresses;
  handshake: Handshake;
}
export interface BitcoinPeer {
  ip: Ip2;
  port: Port2;
  [k: string]: unknown;
}
export interface BitcoinMessage {
  checksum: Checksum;
  command: Command;
  from_addr?: BitcoinAddress;
  lastblock?: Lastblock;
  length: Length1;
  magic_number: MagicNumber;
  nonce?: Nonce;
  relay?: Relay;
  services?: Services1;
  timestamp?: Timestamp2;
  to_addr?: BitcoinAddress;
  user_agent?: UserAgent;
  version?: Version3;
  [k: string]: unknown;
}
export interface BitcoinAddress {
  ipv4: Ipv4;
  ipv6: Ipv61;
  port: Port3;
  services: Services;
  timestamp?: Timestamp1;
  [k: string]: unknown;
}
/**
 * Cassandra databases that allow Thrift connections
 */
export interface Cassandra {
  name: Name3;
  keyspaces: Keyspaces;
  partitioner: Partitioner;
  snitch: Snitch;
  version?: Version4;
  thrift_api_version?: ThriftApiVersion;
}
export interface Checkpoint {
  firewall_host: FirewallHost;
  smartcenter_host: SmartcenterHost;
}
export interface Chromecast {
  build_info?: ChromecastBuildInfo;
  device_info?: ChromecastDeviceInfo;
  net?: ChromecastNet;
  version: Version5;
  wifi?: ChromecastWifi;
  [k: string]: unknown;
}
export interface ChromecastBuildInfo {
  build_type?: BuildType;
  cast_build_revision?: CastBuildRevision;
  cast_control_version?: CastControlVersion;
  release_track?: ReleaseTrack;
  system_build_number?: SystemBuildNumber;
  [k: string]: unknown;
}
export interface ChromecastDeviceInfo {
  cloud_device_id?: CloudDeviceId;
  device_name?: DeviceName;
  hotspot_bssid?: HotspotBssid;
  mac_address?: MacAddress1;
  manufacturer?: Manufacturer1;
  model_name?: ModelName;
  product_name?: ProductName;
  public_key?: PublicKey;
  ssdp_udn?: SsdpUdn;
  uma_client_id?: UmaClientId;
  [k: string]: unknown;
}
export interface ChromecastNet {
  ethernet_connected?: EthernetConnected;
  ip_address?: IpAddress;
  online?: Online;
  [k: string]: unknown;
}
export interface ChromecastWifi {
  ssid?: Ssid;
  bssid?: Bssid;
  [k: string]: unknown;
}
export interface CiscoAnyconnect {
  config_hash?: ConfigHash;
  group_alias?: GroupAlias;
  tunnel_group?: TunnelGroup;
  version?: Version6;
}
export interface Clickhouse {
  primary_status?: PrimaryStatus;
  replicas_status?: ReplicasStatus;
  required_login: RequiredLogin;
  server_name?: ServerName1;
  version?: Version7;
}
export interface Cloud {
  provider: Provider;
  region?: Region;
  service?: Service;
  [k: string]: unknown;
}
export interface Coap {
  resources: Resources;
}
export interface Resources {
  [k: string]: {
    [k: string]: unknown;
  };
}
export interface CobaltStrikeBeacon {
  x86?: CobaltStrikeBeaconDetails;
  x64?: CobaltStrikeBeaconDetails;
  [k: string]: unknown;
}
export interface CobaltStrikeBeaconDetails {
  beacon_type: BeaconType;
  "dns-beacon.strategy_fail_seconds"?: DnsBeaconStrategyFailSeconds;
  "dns-beacon.strategy_fail_x"?: DnsBeaconStrategyFailX;
  "dns-beacon.strategy_rotate_seconds"?: DnsBeaconStrategyRotateSeconds;
  "http-get.client": HttpGetClient;
  "http-get.uri": HttpGetUri;
  "http-get.verb": HttpGetVerb;
  "http-post.client": HttpPostClient;
  "http-post.uri": HttpPostUri;
  "http-post.verb": HttpPostVerb;
  jitter?: Jitter;
  kill_date?: KillDate;
  maxgetsize: Maxgetsize;
  port: Port4;
  "post-ex.spawnto_x64": PostExSpawntoX64;
  "post-ex.spawnto_x86": PostExSpawntoX86;
  "process-inject.execute"?: ProcessInjectExecute;
  "process-inject.min_alloc"?: ProcessInjectMinAlloc;
  "process-inject.startrwx"?: ProcessInjectStartrwx;
  "process-inject.userwx"?: ProcessInjectUserwx;
  "proxy.behavior"?: ProxyBehavior;
  sleeptime: Sleeptime;
  "stage.cleanup"?: StageCleanup;
  useragent_header: UseragentHeader;
  watermark?: Watermark;
  [k: string]: unknown;
}
export interface Cockroachdb {
  experimental_user_login?: ExperimentalUserLogin;
  node_id?: NodeId;
  oidc_login_enable?: OidcLoginEnable;
  tag?: Tag1;
  version?: Version8;
}
export interface CodeSys {
  product?: Product2;
  os?: Os1;
  os_details?: OsDetails;
}
export interface Consul {
  Datacenter?: Datacenter;
  NodeID?: Nodeid;
  NodeName?: Nodename;
  PrimaryDatacenter?: Primarydatacenter;
  Revision?: Revision;
  Server: Server;
  Version?: Version9;
  [k: string]: unknown;
}
export interface CouchbaseServer {
  componentsVersion?: Componentsversion;
  implementationVersion?: Implementationversion;
}
export interface Componentsversion {
  [k: string]: string;
}
export interface CouchbaseSyncGateway {
  couchdb: Couchdb;
  vendor: Vendor2;
  version: Version10;
  persistent_config?: PersistentConfig;
}
export interface Vendor2 {
  [k: string]: string;
}
/**
 * CouchDB servers with authentication disabled.
 */
export interface Couchdb1 {
  couchdb?: Couchdb2;
  features?: Features1;
  git_sha?: GitSha;
  http_headers: HttpHeaders;
  uuid?: Uuid;
  vendor?: Vendor3;
  version?: Version11;
  [k: string]: unknown;
}
export interface Vendor3 {
  [k: string]: string;
}
export interface Dahua {
  serial_number?: SerialNumber1;
}
export interface DahuaDvrWeb {
  channel_names?: ChannelNames;
  plugin?: DahuaDvrWebPlugin;
  user_info?: UserInfo;
  web_version?: WebVersion;
  [k: string]: unknown;
}
export interface DahuaDvrWebPlugin {
  classid: Classid;
  mac_version?: MacVersion;
  name: Name4;
  version: Version12;
  [k: string]: unknown;
}
export interface Dav {
  allowed_methods?: AllowedMethods;
  ips?: Ips;
  paths?: Paths;
  public_options?: PublicOptions;
  server_date?: ServerDate;
  server_type?: ServerType;
  webdav_type?: WebdavType;
}
export interface Dns {
  recursive: Recursive;
  resolver_hostname?: ResolverHostname;
  resolver_id?: ResolverId;
  software?: Software;
}
/**
 * Docker services that allow remote connections and don’t have authentication enabled.
 */
export interface Docker {
  ApiVersion: Apiversion;
  Arch: Arch;
  BuildTime: Buildtime;
  GitCommit: Gitcommit;
  GoVersion: Goversion;
  KernelVersion: Kernelversion;
  MinAPIVersion: Minapiversion;
  Os: Os2;
  Version: Version13;
  [k: string]: unknown;
}
export interface DockerRegistry {
  error?: Error;
  repositories?: Repositories;
}
export interface Domoticz {
  build_time?: BuildTime;
  dzevents_version?: DzeventsVersion;
  hash?: Hash2;
  python_version?: PythonVersion;
  version?: Version14;
  [k: string]: unknown;
}
export interface DraytekVigor {
  build_time: BuildTime1;
}
export interface Elastic {
  cluster?: Cluster;
  indices?: Indices;
  nodes?: Nodes;
  [k: string]: unknown;
}
export interface Cluster {
  [k: string]: unknown;
}
export interface Indices {
  [k: string]: unknown;
}
export interface Nodes {
  [k: string]: unknown;
}
/**
 * Erlang Port Mapper Daemon
 */
export interface Epmd {
  nodes: Nodes1;
}
export interface Nodes1 {
  [k: string]: number;
}
export interface Etcd {
  api: Api;
  clientURLs?: Clienturls;
  dbSize?: Dbsize;
  id: Id1;
  leaderInfo?: Leaderinfo;
  name: Name5;
  peerURLs?: Peerurls;
  recvAppendRequestCnt?: Recvappendrequestcnt;
  recvBandwidthRate?: Recvbandwidthrate;
  recvPkgRate?: Recvpkgrate;
  sendAppendRequestCnt?: Sendappendrequestcnt;
  sendBandwidthRate?: Sendbandwidthrate;
  sendPkgRate?: Sendpkgrate;
  startTime?: Starttime;
  state?: State;
  version?: Version15;
}
export interface Leaderinfo {
  [k: string]: string;
}
export interface EthereumP2P {
  pubkey: Pubkey;
  version?: Version16;
  tcp_port?: TcpPort;
  udp_port?: UdpPort;
  neighbors?: Neighbors;
}
export interface EthereumP2PNeighbour {
  ip: Ip3;
  pubkey: Pubkey1;
  tcp_port: TcpPort1;
  udp_port: UdpPort1;
  [k: string]: unknown;
}
export interface EthereumRpc {
  client: Client;
  version?: Version17;
  platform?: Platform2;
  compiler?: Compiler;
  hashrate?: Hashrate;
  chain_id?: ChainId;
  accounts?: Accounts;
}
export interface Ethernetip {
  command: Command1;
  command_length: CommandLength;
  command_status: CommandStatus;
  device_type: DeviceType;
  encapsulation_length: EncapsulationLength;
  ip: Ip4;
  item_count: ItemCount;
  options: Options;
  product_code: ProductCode;
  product_name: ProductName1;
  product_name_length: ProductNameLength;
  raw: Raw;
  revision_major: RevisionMajor;
  revision_minor: RevisionMinor;
  sender_context: SenderContext;
  serial: Serial;
  session: Session;
  socket_addr: SocketAddr;
  state: State1;
  status: Status;
  type_id: TypeId;
  vendor_id: VendorId;
  version: Version18;
}
export interface Fortinet {
  device?: Device2;
  serial_number?: SerialNumber2;
  model?: Model2;
}
export interface Ftp {
  anonymous: Anonymous;
  features: Features2;
  features_hash?: FeaturesHash;
}
export interface Features2 {
  [k: string]: FtpFeature;
}
export interface FtpFeature {
  parameters: Parameters;
  [k: string]: unknown;
}
export interface Ganglia {
  clusters?: Clusters;
  version?: Version19;
}
export interface GangliaCluster {
  owner?: Owner;
  hosts?: Hosts;
  name?: Name6;
  [k: string]: unknown;
}
export interface Handpunch {
  adapter_type: AdapterType;
  eprom_version: EpromVersion;
  max_logs: MaxLogs;
  max_users: MaxUsers;
  memory_size: MemorySize;
  model: Model3;
  model_name: ModelName1;
  serial_number: SerialNumber3;
  total_logs: TotalLogs;
  total_users: TotalUsers;
}
export interface HBase {
  cluster_key?: ClusterKey;
  coprocessors?: Coprocessors;
  hadoop_compiled?: HadoopCompiled;
  hadoop_source_checksum?: HadoopSourceChecksum;
  hadoop_version?: HadoopVersion;
  hbase_cluster_id?: HbaseClusterId;
  hbase_compiled?: HbaseCompiled;
  hbase_source_checksum?: HbaseSourceChecksum;
  hbase_root_directory?: HbaseRootDirectory;
  hbase_version?: HbaseVersion;
  hmaster_active_time?: HmasterActiveTime;
  hmaster_start_time?: HmasterStartTime;
  jvm_version?: JvmVersion;
  load_average?: LoadAverage;
  loadbalancer?: Loadbalancer;
  rest_server_start_time?: RestServerStartTime;
  zookeeper_base_path?: ZookeeperBasePath;
  zookeeper_client_compiled?: ZookeeperClientCompiled;
  zookeeper_client_version?: ZookeeperClientVersion;
  zookeeper_quorum?: ZookeeperQuorum;
  hbase_master?: HbaseMaster;
  rs_start_time?: RsStartTime;
}
export interface Hikvision {
  activex_files?: ActivexFiles;
  custom_version?: CustomVersion;
  custom_version_2?: CustomVersion2;
  device_description?: DeviceDescription;
  device_model?: DeviceModel1;
  device_name?: DeviceName1;
  device_version?: DeviceVersion;
  plugin_version?: PluginVersion;
  web_version?: WebVersion1;
  [k: string]: unknown;
}
export interface ActivexFiles {
  [k: string]: string;
}
export interface ApacheHive {
  databases: Databases;
}
export interface ApacheHiveDatabase {
  tables: Tables;
  [k: string]: unknown;
}
export interface ApacheHiveTable {
  name: Name7;
  properties: Properties;
  [k: string]: unknown;
}
export interface HomeAssistant {
  base_url?: BaseUrl;
  external_url?: ExternalUrl;
  location_name?: LocationName;
  installation_type?: InstallationType;
  internal_url?: InternalUrl;
  uuid?: Uuid1;
  version?: Version20;
  [k: string]: unknown;
}
export interface Homebridge {
  enable_terminal_access: EnableTerminalAccess;
  enable_accessories: EnableAccessories;
  instance_id?: InstanceId1;
  instance_name: InstanceName;
  node_version: NodeVersion;
  platform?: Platform3;
  running_in_docker: RunningInDocker;
  running_in_linux: RunningInLinux;
  service_mode?: ServiceMode;
  ui_package_name: UiPackageName;
  ui_package_version: UiPackageVersion;
  [k: string]: unknown;
}
export interface Hoobs {
  bridge?: HoobsBridge;
  client?: HoobsClient;
  server?: HoobsServer;
  [k: string]: unknown;
}
export interface HoobsBridge {
  name: Name8;
  pin: Pin;
  port: Port5;
  username: Username;
  [k: string]: unknown;
}
export interface HoobsClient {
  country_code: CountryCode1;
  postal_code?: PostalCode1;
  [k: string]: unknown;
}
export interface HoobsServer {
  application_path?: ApplicationPath;
  configuration_path?: ConfigurationPath;
  global_modules_path?: GlobalModulesPath;
  home_setup_id?: HomeSetupId;
  hoobs_version?: HoobsVersion;
  local_modules_path?: LocalModulesPath;
  node_version: NodeVersion1;
  port?: Port6;
  [k: string]: unknown;
}
export interface HpIlo {
  cuuid?: Cuuid;
  ilo_firmware: IloFirmware;
  ilo_serial_number: IloSerialNumber;
  ilo_type: IloType;
  ilo_uuid: IloUuid;
  nics?: Nics;
  product_id?: ProductId;
  serial_number?: SerialNumber4;
  server_type?: ServerType1;
  uuid?: Uuid2;
  [k: string]: unknown;
}
export interface HpIloNic {
  description?: Description;
  ip_address?: IpAddress1;
  location?: Location2;
  mac_address?: MacAddress2;
  port: Port7;
  status?: Status1;
  [k: string]: unknown;
}
export interface HpeOneView {
  minimum_version: MinimumVersion;
  current_version: CurrentVersion;
}
export interface Http {
  components?: Components;
  favicon?: Favicon;
  headers_hash?: HeadersHash;
  host?: Host;
  html?: Html1;
  html_hash?: HtmlHash;
  location?: Location4;
  redirects: Redirects;
  robots?: Robots;
  robots_hash?: RobotsHash;
  securitytxt?: Securitytxt;
  securitytxt_hash?: SecuritytxtHash;
  server?: Server1;
  sitemap?: Sitemap;
  sitemap_hash?: SitemapHash;
  status?: Status2;
  title?: Title1;
  waf?: Waf;
}
/**
 * The web technologies (ex. jQuery) that a website uses.
 */
export interface Components {
  [k: string]: HttpComponent;
}
export interface HttpComponent {
  categories: Categories;
  [k: string]: unknown;
}
export interface HttpFavicon {
  data: Data2;
  hash: Hash3;
  location: Location3;
  [k: string]: unknown;
}
export interface HttpRedirect {
  data?: Data3;
  host: Host1;
  location: Location5;
  [k: string]: unknown;
}
export interface Hubitat {
  hardware_version?: HardwareVersion;
  hub_uid?: HubUid;
  ip_address?: IpAddress2;
  mac_address?: MacAddress3;
  version: Version21;
  [k: string]: unknown;
}
export interface IbmDb2 {
  db2_version: Db2Version;
  instance_name: InstanceName1;
  server_platform: ServerPlatform;
  external_name: ExternalName;
}
export interface Influxdb {
  bind_address?: BindAddress;
  build?: Build;
  databases?: Databases1;
  go_arch?: GoArch;
  go_max_procs?: GoMaxProcs;
  go_os?: GoOs;
  go_version?: GoVersion;
  network_hostname?: NetworkHostname;
  uptime?: Uptime1;
  version?: Version22;
  [k: string]: unknown;
}
export interface Iota {
  [k: string]: unknown;
}
export interface IpCamera {
  alias_name?: AliasName;
  app_version?: AppVersion;
  brand?: Brand;
  build?: Build1;
  client_version?: ClientVersion;
  ddns_host?: DdnsHost;
  hardware_version?: HardwareVersion1;
  id?: Id2;
  ip_address?: IpAddress3;
  mac_address?: MacAddress4;
  model?: Model4;
  name?: Name9;
  product?: Product3;
  server_version?: ServerVersion;
  software_version?: SoftwareVersion;
  system_version?: SystemVersion;
  version?: Version23;
  [k: string]: unknown;
}
export interface IpSymcon {
  api_version: ApiVersion;
  houses?: Houses;
  version: Version24;
  [k: string]: unknown;
}
export interface IpSymconHouse {
  name: Name10;
  password: Password;
  [k: string]: unknown;
}
export interface Ipmi {
  user_auth?: UserAuth;
  version?: Version25;
  password_auth?: PasswordAuth;
  level?: Level;
  oemid?: Oemid;
}
export interface IppCups {
  printers?: Printers;
  status_message?: StatusMessage;
  [k: string]: unknown;
}
export interface IppCupsPrinter {
  authentication_type?: AuthenticationType;
  dns_sd_name?: DnsSdName;
  info?: Info1;
  make_and_model?: MakeAndModel;
  name?: Name11;
  uri_supported: UriSupported;
  [k: string]: unknown;
}
export interface Isakmp {
  aggressive?: Isakmp;
  exchange_type: ExchangeType;
  flags: IsakmpFlags;
  initiator_spi: InitiatorSpi;
  length: Length2;
  msg_id: MsgId;
  next_payload: NextPayload;
  responder_spi: ResponderSpi;
  vendor_ids: VendorIds;
  version: Version26;
}
export interface IsakmpFlags {
  authentication: Authentication;
  commit: Commit;
  encryption: Encryption;
  [k: string]: unknown;
}
export interface Iscsi {
  targets: Targets;
}
export interface IscsiTarget {
  addresses?: Addresses1;
  auth_enabled?: AuthEnabled;
  auth_error?: AuthError;
  name: Name12;
  [k: string]: unknown;
}
export interface Kafka {
  brokers: Brokers;
  hosts: Hosts1;
  topics: Topics;
}
export interface KafkaBroker {
  id: Id3;
  name: Name13;
  port: Port8;
  rack?: Rack;
  [k: string]: unknown;
}
export interface KafkaHost {
  name: Name14;
  port: Port9;
  [k: string]: unknown;
}
export interface Knx {
  device: KnxDevice;
  supported_services: KnxServices;
}
export interface KnxDevice {
  friendly_name: FriendlyName;
  knx_address: KnxAddress;
  mac: Mac1;
  multicast_address: MulticastAddress;
  serial: Serial1;
  [k: string]: unknown;
}
export interface KnxServices {
  core: Core;
  device_management?: DeviceManagement;
  routing?: Routing;
  tunneling?: Tunneling;
  [k: string]: unknown;
}
export interface Kubernetes {
  build_date?: BuildDate;
  go_version?: GoVersion1;
  nodes?: Nodes2;
  platform?: Platform4;
  version?: Version27;
  [k: string]: unknown;
}
export interface KubernetesNode {
  name: Name15;
  containers: Containers;
  [k: string]: unknown;
}
export interface KubernetesContainer {
  image: Image;
  name: Name16;
  [k: string]: unknown;
}
export interface Mpd {
  uptime?: Uptime2;
  db_update?: DbUpdate;
  suffix?: Suffix;
  artists?: Artists;
  plugin?: Plugin;
  playtime?: Playtime;
  albums?: Albums;
  songs?: Songs;
  mime_type?: MimeType;
  db_playtime?: DbPlaytime;
}
export interface Lantronix {
  gateway?: Gateway;
  ip?: Ip5;
  mac?: Mac2;
  password?: Password1;
  type?: Type1;
  version?: Version28;
}
export interface Ldap {
  configurationNamingContext?: Configurationnamingcontext;
  currenttime?: Currenttime;
  currentTime?: Currenttime1;
  defaultNamingContext?: Defaultnamingcontext;
  dnsHostName?: Dnshostname;
  domainFunctionality?: Domainfunctionality;
  dsServiceName?: Dsservicename;
  forestFunctionality?: Forestfunctionality;
  highestCommittedUSN?: Highestcommittedusn;
  isGlobalCatalogReady?: Isglobalcatalogready;
  isSynchronized?: Issynchronized;
  ldapServiceName?: Ldapservicename;
  rootDomainNamingContext?: Rootdomainnamingcontext;
  schemaNamingContext?: Schemanamingcontext;
  serverName?: Servername;
  supportedCapabilities?: Supportedcapabilities;
  supportedLDAPPolicies?: Supportedldappolicies;
  errorMessage?: Errormessage;
  namingContexts?: Namingcontexts;
  resultCode?: Resultcode;
  subschemaSubentry?: Subschemasubentry;
  subSchemaSubEntry?: Subschemasubentry1;
  supportedControl?: Supportedcontrol;
  supportedExtension?: Supportedextension;
  supportedLDAPVersion?: Supportedldapversion;
  supportedLDAPversion?: Supportedldapversion1;
  supportedLdapVersion?: Supportedldapversion2;
  supportedSASLMechanisms?: Supportedsaslmechanisms;
  namingcontexts?: Namingcontexts1;
  subschemasubentry?: Subschemasubentry2;
  supportedcontrol?: Supportedcontrol1;
  supportedextension?: Supportedextension1;
  supportedldapversion?: Supportedldapversion3;
  supportedsaslmechanisms?: Supportedsaslmechanisms1;
  dNSHostName?: Dnshostname1;
  altServer?: Altserver;
  objectClass?: Objectclass;
  domainControllerFunctionality?: Domaincontrollerfunctionality;
}
export interface Mdns {
  additionals?: Additionals;
  answers?: Answers;
  authorities?: Authorities;
  services?: Services2;
}
export interface Additionals {
  [k: string]: string[] | string;
}
export interface Answers {
  [k: string]: string[] | string;
}
export interface Authorities {
  [k: string]: string[] | string;
}
export interface Services2 {
  [k: string]: MdnsService;
}
export interface MdnsService {
  ipv4?: Ipv41;
  ipv6?: Ipv62;
  name?: Name17;
  port?: Port10;
  ptr: Ptr1;
  [k: string]: unknown;
}
export interface MicrosoftExchange {
  build_date?: BuildDate1;
  build_number?: BuildNumber;
  name?: Name18;
}
export interface MikrotikRouteros {
  interfaces?: Interfaces;
  version: Version29;
  [k: string]: unknown;
}
export interface MikrotikWinbox {
  index?: Index;
  list?: List;
}
export interface Index {
  [k: string]: MikrotikWinboxLib;
}
export interface MikrotikWinboxLib {
  crc: Crc;
  size: Size;
  version?: Version30;
  [k: string]: unknown;
}
export interface List {
  [k: string]: MikrotikWinboxLib;
}
export interface Minecraft {
  brand?: Brand1;
  description?: Description1;
  enforcesSecureChat?: Enforcessecurechat;
  favicon?: Favicon1;
  forgeData?: Forgedata;
  gamemode?: Gamemode;
  lcServer?: Lcserver;
  map?: Map;
  modinfo?: Modinfo;
  modpackData?: Modpackdata;
  players?: MinecraftPlayers;
  preventsChatReports?: Preventschatreports;
  previewsChat?: Previewschat;
  translate?: Translate1;
  version?: MinecraftVersion;
  with?: With;
}
export interface MinecraftDescription {
  extra?: Extra;
  text?: Text1;
  translate?: Translate;
  [k: string]: unknown;
}
export interface Forgedata {
  [k: string]: unknown;
}
export interface Modinfo {
  [k: string]: unknown;
}
export interface Modpackdata {
  [k: string]: unknown;
}
export interface MinecraftPlayers {
  max: Max;
  online: Online1;
  sample?: Sample;
  [k: string]: unknown;
}
export interface MinecraftPlayer {
  id: Id4;
  name: Name19;
  [k: string]: unknown;
}
export interface MinecraftVersion {
  name: Name20;
  protocol: Protocol;
  [k: string]: unknown;
}
export interface MitsubishiQ {
  cpu: Cpu;
}
export interface Monero {
  [k: string]: unknown;
}
export interface Mongodb {
  authentication: Authentication1;
  buildInfo?: Buildinfo;
  listDatabases?: Listdatabases;
  serverStatus?: Serverstatus;
}
export interface Buildinfo {
  [k: string]: unknown;
}
export interface Listdatabases {
  [k: string]: unknown;
}
export interface Serverstatus {
  [k: string]: unknown;
}
export interface Msrpc {
  actual_count: ActualCount;
  max_count?: MaxCount;
  num_towers?: NumTowers;
  towers: Towers;
}
export interface Towers {
  [k: string]: MsrpcTower;
}
export interface MsrpcTower {
  annotation?: Annotation;
  bindings: Bindings;
  version?: Version31;
  [k: string]: unknown;
}
export interface Mssql {
  dns_computer_name?: DnsComputerName;
  dns_domain_name?: DnsDomainName;
  netbios_computer_name?: NetbiosComputerName;
  netbios_domain_name?: NetbiosDomainName;
  os_version: OsVersion1;
  target_realm?: TargetRealm;
  timestamp?: Timestamp3;
}
export interface MssqlSsrp {
  instances: Instances;
}
export interface MssqlSsrpInstance {
  instance_name: InstanceName2;
  is_clustered?: IsClustered;
  server_name: ServerName2;
  tcp?: Tcp;
  version: Version32;
  version_name?: VersionName;
  [k: string]: unknown;
}
export interface Mqtt {
  code: Code;
  messages: Messages1;
}
export interface MqttMessage {
  payload?: Payload;
  topic: Topic;
  [k: string]: unknown;
}
export interface Mysql {
  authentication_plugin?: AuthenticationPlugin;
  capabilities?: Capabilities;
  error_code?: ErrorCode1;
  error_message?: ErrorMessage;
  extended_server_capabilities?: ExtendedServerCapabilities;
  protocol_version?: ProtocolVersion1;
  server_language?: ServerLanguage;
  server_status?: ServerStatus;
  thread_id?: ThreadId;
  version?: Version33;
}
export interface Mysqlx {
  tls?: Tls;
  "client.pwd_expire_ok": ClientPwdExpireOk;
  compression?: MysqlxCompression;
  "doc.formats": DocFormats;
  node_type: NodeType;
  "client.interactive": ClientInteractive;
  "authentication.mechanisms": AuthenticationMechanisms;
}
export interface MysqlxCompression {
  algorithm: Algorithm;
  [k: string]: unknown;
}
export interface Nats {
  auth_required?: AuthRequired;
  client_id?: ClientId;
  client_ip?: ClientIp;
  cluster?: Cluster1;
  connection_id?: ConnectionId;
  git_commit?: GitCommit;
  go?: Go;
  headers?: Headers;
  host: Host2;
  jetstream?: Jetstream;
  lnoc?: Lnoc;
  max_payload?: MaxPayload;
  nonce?: Nonce1;
  port: Port11;
  proto?: Proto;
  server_id?: ServerId;
  server_name?: ServerName3;
  tls_required?: TlsRequired;
  tls_verify?: TlsVerify;
  version: Version34;
  connect_urls?: ConnectUrls;
  ip?: Ip6;
  leafnode_urls?: LeafnodeUrls;
  xkey?: Xkey;
}
export interface Ndmp {
  devices: Devices;
}
export interface NdmpDevice {
  fs_logical_device: FsLogicalDevice;
  fs_physical_device: FsPhysicalDevice;
  fs_type: FsType;
  [k: string]: unknown;
}
export interface Neo4JBrowser {
  build_number?: BuildNumber1;
  built_at?: BuiltAt;
  version?: Version35;
}
export interface Netbios {
  mac?: Mac3;
  names?: Names;
  networks?: Networks;
  raw: Raw1;
  server_name?: ServerName4;
  username?: Username1;
}
export interface NetbiosShare {
  flags: Flags;
  name?: Name21;
  suffix: Suffix1;
  [k: string]: unknown;
}
export interface Netgear {
  description: Description2;
  firewall_version: FirewallVersion;
  firmware_version: FirmwareVersion1;
  first_use_date: FirstUseDate;
  model_name: ModelName2;
  serial_number?: SerialNumber5;
  smartagent_version: SmartagentVersion;
  vpn_version?: VpnVersion;
  [k: string]: unknown;
}
export interface NodeExporter {
  node_exporter_build_info?: NodeExporterBuild;
  node_uname_info?: NodeExporterUname;
  node_os_info?: NodeExporterOs;
  node_dmi_info?: NodeExporterDmi;
  node_network_info?: NodeNetworkInfo;
  node_nvme_info?: NodeNvmeInfo;
  node_infiniband_info?: NodeInfinibandInfo;
}
export interface NodeExporterBuild {
  branch?: Branch;
  goversion?: Goversion1;
  revision?: Revision1;
  version?: Version36;
  [k: string]: unknown;
}
export interface NodeExporterUname {
  domainname?: Domainname;
  machine?: Machine;
  nodename?: Nodename1;
  release?: Release;
  sysname?: Sysname;
  version?: Version37;
  [k: string]: unknown;
}
export interface NodeExporterOs {
  name?: Name22;
  pretty_name?: PrettyName;
  id_like?: IdLike;
  version_id?: VersionId;
  version_codename?: VersionCodename;
  version?: Version38;
  id?: Id5;
  [k: string]: unknown;
}
export interface NodeExporterDmi {
  chassis_version?: ChassisVersion;
  bios_vendor?: BiosVendor;
  product_version?: ProductVersion;
  system_vendor?: SystemVendor;
  bios_release?: BiosRelease;
  bios_date?: BiosDate;
  bios_version?: BiosVersion;
  chassis_vendor?: ChassisVendor;
  product_name?: ProductName2;
  product_family?: ProductFamily;
  [k: string]: unknown;
}
export interface NodeNetworkInfo {
  [k: string]: NodeExporterNetwork;
}
export interface NodeExporterNetwork {
  broadcast?: Broadcast;
  device?: Device3;
  operstate?: Operstate;
  address?: Address;
  duplex?: Duplex;
  [k: string]: unknown;
}
export interface NodeNvmeInfo {
  [k: string]: NodeExporterNvme;
}
export interface NodeExporterNvme {
  device?: Device4;
  firmware_revision?: FirmwareRevision;
  model?: Model5;
  serial?: Serial2;
  state?: State2;
  [k: string]: unknown;
}
export interface NodeInfinibandInfo {
  [k: string]: NodeExporterInfiniband;
}
export interface NodeExporterInfiniband {
  board_id?: BoardId;
  device?: Device5;
  firmware_version?: FirmwareVersion2;
  hca_type?: HcaType;
  [k: string]: unknown;
}
export interface Ntlm {
  dns_domain_name?: DnsDomainName1;
  dns_forest_name?: DnsForestName;
  fqdn?: Fqdn;
  netbios_computer_name?: NetbiosComputerName1;
  netbios_domain_name?: NetbiosDomainName1;
  os?: Os3;
  os_build?: OsBuild;
  target_realm?: TargetRealm1;
  timestamp?: Timestamp4;
}
export interface Ntp {
  clk_jitter?: ClkJitter;
  clk_wander?: ClkWander;
  clock?: Clock;
  clock_offset: ClockOffset;
  delay: Delay;
  frequency?: Frequency;
  jitter?: Jitter1;
  leap: Leap;
  mintc?: Mintc;
  monlist?: NtpMonlist;
  noise?: Noise;
  offset?: Offset;
  peer?: Peer;
  phase?: Phase;
  poll: Poll;
  precision: Precision;
  processor?: Processor;
  refid: Refid;
  reftime: Reftime;
  root_delay: RootDelay;
  root_dispersion: RootDispersion;
  rootdelay?: Rootdelay;
  rootdisp?: Rootdisp;
  stability?: Stability;
  state?: State3;
  stratum: Stratum;
  sys_jitter?: SysJitter;
  system?: System;
  tai?: Tai;
  tc?: Tc;
  version: Version39;
  [k: string]: unknown;
}
export interface NtpMonlist {
  connections: Connections;
  more: More;
  [k: string]: unknown;
}
export interface Openflow {
  supported_versions?: SupportedVersions;
  version: Version40;
}
export interface Openhab {
  build: Build2;
  version: Version41;
  [k: string]: unknown;
}
export interface Openwebnet {
  date_and_time: DateAndTime;
  device_type: DeviceType1;
  distribution_version?: DistributionVersion;
  firmware_version: FirmwareVersion3;
  ip_address: IpAddress4;
  kernel_version: KernelVersion;
  mac_address: MacAddress5;
  net_mask: NetMask;
  systems: OpenwebnetSystems;
  uptime: Uptime3;
  [k: string]: unknown;
}
export interface OpenwebnetSystems {
  automation: Automation;
  burglar_alarm?: BurglarAlarm;
  heating: Heating;
  lighting: Lighting;
  power_management: PowerManagement;
  [k: string]: unknown;
}
export interface OracleTnsListener {
  description: OracleTnsListenerDescription;
  versions?: Versions;
}
export interface OracleTnsListenerDescription {
  err?: Err;
  error_stack?: ErrorStack;
  vsnnum?: Vsnnum;
  [k: string]: unknown;
}
export interface ErrorStack {
  [k: string]: {
    [k: string]: unknown;
  };
}
export interface Versions {
  [k: string]: string;
}
export interface Pcworx {
  firmware_date: FirmwareDate;
  firmware_time: FirmwareTime;
  firmware_version: FirmwareVersion4;
  model_number: ModelNumber;
  plc_type: PlcType;
}
export interface PhilipsHue {
  api_version: ApiVersion1;
  bridge_id: BridgeId;
  data_store_version?: DataStoreVersion;
  factory_new: FactoryNew;
  mac: Mac4;
  model_id: ModelId;
  name: Name23;
  sw_version: SwVersion;
  [k: string]: unknown;
}
export interface Plex {
  machine_identifier?: MachineIdentifier;
  version?: Version42;
  [k: string]: unknown;
}
export interface Pptp {
  firmware: Firmware1;
  hostname: Hostname1;
  vendor: Vendor4;
}
export interface Qnap {
  apps?: Apps;
  firmware?: QnapFirmware;
  hostname?: Hostname2;
  model?: QnapModel;
  [k: string]: unknown;
}
export interface Apps {
  [k: string]: QnapStationInfo;
}
export interface QnapStationInfo {
  build: Build3;
  checksum?: Checksum1;
  version?: Version43;
  [k: string]: unknown;
}
export interface QnapFirmware {
  build?: Build4;
  number?: Number;
  patch?: Patch;
  version?: Version44;
  [k: string]: unknown;
}
export interface QnapModel {
  custom_model_name?: CustomModelName;
  display_model_name?: DisplayModelName;
  internal_model_name?: InternalModelName;
  model_name?: ModelName3;
  platform?: Platform5;
  platform_ex?: PlatformEx;
  project_name?: ProjectName;
  [k: string]: unknown;
}
export interface RdpEncryption {
  levels: Levels;
  methods: Methods;
  protocols: Protocols;
}
export interface Realport {
  name: Name24;
  ports?: Ports;
}
export interface Redis {
  clients?: Clients;
  cluster?: Cluster2;
  cpu?: Cpu1;
  errorstats?: Errorstats;
  keys?: RedisKeys;
  keyspace?: Keyspace;
  memory?: Memory;
  modules?: Modules;
  ok?: Ok;
  persistence?: Persistence;
  replication?: Replication;
  server?: Server2;
  ssl?: Ssl;
  stats?: Stats;
  [k: string]: unknown;
}
export interface Cpu1 {
  [k: string]: unknown;
}
export interface Errorstats {
  [k: string]: unknown;
}
export interface RedisKeys {
  data: Data4;
  more: More1;
  [k: string]: unknown;
}
export interface Keyspace {
  [k: string]: string;
}
export interface Memory {
  [k: string]: unknown;
}
export interface Modules {
  [k: string]: unknown;
}
export interface Ok {
  [k: string]: unknown;
}
export interface Persistence {
  [k: string]: unknown;
}
export interface Replication {
  [k: string]: unknown;
}
export interface Server2 {
  [k: string]: unknown;
}
export interface Ssl {
  [k: string]: unknown;
}
export interface Stats {
  [k: string]: unknown;
}
export interface Rip {
  addresses: Addresses2;
  auth?: RipAuthentication;
  command: Command2;
  version: Version45;
}
export interface RipAddress {
  addr: Addr;
  family: Family;
  metric: Metric;
  next_hop?: NextHop;
  subnet?: Subnet;
  tag?: Tag2;
  [k: string]: unknown;
}
export interface RipAuthentication {
  password: Password2;
  type: Type2;
  [k: string]: unknown;
}
export interface Ripple {
  peers: Peers;
}
export interface RipplePeer {
  complete_ledgers?: CompleteLedgers;
  ip?: Ip7;
  port?: Port12;
  public_key: PublicKey1;
  type: Type3;
  uptime: Uptime4;
  version: Version46;
  [k: string]: unknown;
}
export interface Rsync {
  authentication: Authentication2;
  modules: Modules1;
}
export interface Modules1 {
  [k: string]: string;
}
export interface SamsungTv {
  device_id?: DeviceId1;
  device_name: DeviceName2;
  model?: Model6;
  model_description: ModelDescription;
  model_name: ModelName4;
  msf_version?: MsfVersion;
  ssid?: Ssid1;
  wifi_mac?: WifiMac;
  [k: string]: unknown;
}
export interface SiemensS7 {
  dst_tsap: DstTsap;
  identities: Identities;
  src_tsap: SrcTsap;
}
export interface Identities {
  [k: string]: SiemensS7Property;
}
export interface SiemensS7Property {
  raw: Raw2;
  value: Value;
  [k: string]: unknown;
}
export interface Smb {
  anonymous?: Anonymous1;
  capabilities: Capabilities1;
  os?: Os4;
  raw: Raw3;
  shares?: Shares;
  software?: Software1;
  smb_version: SmbVersion;
}
export interface SmbItem {
  comments: Comments;
  files?: Files;
  name: Name26;
  special: Special;
  temporary: Temporary;
  type: Type4;
  [k: string]: unknown;
}
export interface SmbFile {
  directory: Directory;
  name: Name25;
  "read-only": ReadOnly;
  size: Size1;
  [k: string]: unknown;
}
export interface Snmp {
  contact?: Contact;
  description?: Description3;
  location?: Location6;
  name?: Name27;
  objectid?: Objectid;
  ordescr?: Ordescr;
  orid?: Orid;
  orindex?: Orindex;
  orlastchange?: Orlastchange;
  oruptime?: Oruptime;
  uptime?: Uptime5;
  services?: Services3;
  [k: string]: unknown;
}
export interface Sonicwall {
  sonicos_version?: SonicosVersion;
  serial_number?: SerialNumber6;
  [k: string]: unknown;
}
export interface Sonos {
  friendly_name: FriendlyName1;
  hardware_version: HardwareVersion2;
  mac_address?: MacAddress6;
  model_name: ModelName5;
  raw: Raw4;
  room_name: RoomName;
  serial_number: SerialNumber7;
  software_version: SoftwareVersion1;
  udn: Udn;
  [k: string]: unknown;
}
export interface SonyBravia {
  interface_version: InterfaceVersion;
  model_name: ModelName6;
  mac_address?: MacAddress7;
  [k: string]: unknown;
}
export interface SpotifyConnect {
  active_user?: ActiveUser;
  brand_display_name?: BrandDisplayName;
  client_id?: ClientId1;
  device_id?: DeviceId2;
  device_type?: DeviceType2;
  library_version?: LibraryVersion;
  model_display_name?: ModelDisplayName;
  remote_name?: RemoteName;
  public_key?: PublicKey2;
  scope?: Scope;
  version: Version47;
  [k: string]: unknown;
}
export interface Ssh {
  cipher: Cipher;
  fingerprint: Fingerprint;
  hassh: Hassh;
  kex: SshKeyExchange;
  key: Key;
  mac: Mac5;
  type: Type5;
}
export interface SshKeyExchange {
  compression_algorithms: CompressionAlgorithms;
  encryption_algorithms: EncryptionAlgorithms;
  kex_algorithms: KexAlgorithms;
  kex_follows: KexFollows;
  languages: Languages;
  mac_algorithms: MacAlgorithms;
  server_host_key_algorithms: ServerHostKeyAlgorithms;
  unused: Unused;
  [k: string]: unknown;
}
export interface Ssl1 {
  acceptable_cas?: AcceptableCas;
  alpn?: Alpn;
  cert?: SslCertificate;
  chain?: Chain;
  chain_sha256?: ChainSha256;
  cipher?: Cipher1;
  dhparams?: SslDhparams;
  handshake_states?: HandshakeStates;
  ja3s?: Ja3S;
  jarm?: Jarm;
  ocsp?: Ocsp;
  tlsext?: Tlsext;
  trust?: SslBrowserTrust;
  unstable?: Unstable;
  versions?: Versions1;
}
export interface SslCas {
  components: Components1;
  hash: Hash4;
  raw: Raw5;
  [k: string]: unknown;
}
export interface Components1 {
  [k: string]: unknown;
}
export interface SslCertificate {
  expired: Expired;
  expires: Expires;
  extensions: Extensions;
  fingerprint: SslCertificateFingerprint;
  issuer: Issuer;
  issued?: Issued;
  serial: Serial3;
  sig_alg: SigAlg;
  subject: Subject;
  version: Version48;
  [k: string]: unknown;
}
export interface SslCertificateExtension {
  critical?: Critical;
  data: Data5;
  name: Name28;
  [k: string]: unknown;
}
export interface SslCertificateFingerprint {
  sha1: Sha1;
  sha256: Sha256;
  [k: string]: unknown;
}
export interface Issuer {
  [k: string]: string;
}
export interface Subject {
  [k: string]: string;
}
export interface SslCipher {
  bits: Bits;
  name: Name29;
  version: Version49;
  [k: string]: unknown;
}
export interface SslDhparams {
  bits: Bits1;
  fingerprint?: Fingerprint1;
  generator: Generator;
  prime: Prime;
  public_key: PublicKey3;
  [k: string]: unknown;
}
export interface SslOcsp {
  certificate_id: SslOcspCertId;
  cert_status: CertStatus;
  next_update: NextUpdate;
  produced_at: ProducedAt;
  responder_id: ResponderId;
  response_status: ResponseStatus;
  signature_algorithm: SignatureAlgorithm;
  this_update: ThisUpdate;
  version: Version50;
  [k: string]: unknown;
}
export interface SslOcspCertId {
  hash_algorithm: HashAlgorithm;
  issuer_name_hash: IssuerNameHash;
  issuer_name_key: IssuerNameKey;
  serial_number: SerialNumber8;
  [k: string]: unknown;
}
export interface SslExtension {
  id: Id6;
  name: Name30;
  [k: string]: unknown;
}
export interface SslBrowserTrust {
  browser?: SslBrowserTrustVendor;
  revoked?: Revoked;
  [k: string]: unknown;
}
export interface SslBrowserTrustVendor {
  apple: Apple;
  microsoft: Microsoft;
  mozilla: Mozilla;
  [k: string]: unknown;
}
export interface SteamA2S {
  address?: Address1;
  app_id?: AppId;
  client_dll?: ClientDll;
  game_port?: GamePort;
  is_mod?: IsMod;
  map: Map1;
  mod_size?: ModSize;
  mod_version?: ModVersion;
  name: Name31;
  protocol?: Protocol1;
  server_type: ServerType2;
  folder: Folder;
  players: Players;
  game: Game;
  version: Version51;
  max_players: MaxPlayers;
  password?: Password3;
  os: Os5;
  bots: Bots;
  secure: Secure;
  server_only?: ServerOnly;
  spec_port?: SpecPort;
  spec_name?: SpecName;
  steam_id?: SteamId;
  tags?: Tags;
  url_download?: UrlDownload;
  url_info?: UrlInfo;
  visibility?: Visibility;
}
export interface SteamIhs {
  client_id?: ClientId2;
  connect_port?: ConnectPort;
  enabled_services?: EnabledServices;
  euniverse?: Euniverse;
  hostname?: Hostname3;
  instance_id?: InstanceId2;
  ip_addresses?: IpAddresses;
  is_64bit?: Is64Bit;
  mac_addresses?: MacAddresses;
  min_version?: MinVersion;
  os_type?: OsType;
  public_ip_address?: PublicIpAddress;
  timestamp?: Timestamp5;
  users?: Users;
  version: Version52;
}
export interface SteamIhsUser {
  auth_key_id: AuthKeyId;
  steam_id: SteamId1;
  [k: string]: unknown;
}
export interface Stun {
  server_ip?: ServerIp;
  software?: Software2;
}
export interface Synology {
  hostname?: Hostname4;
  custom_login_title?: CustomLoginTitle;
  login_welcome_title?: LoginWelcomeTitle;
  login_welcome_msg?: LoginWelcomeMsg;
  version?: Version53;
  [k: string]: unknown;
}
export interface Tacacs {
  flags: Flags1;
  length: Length3;
  sequence: Sequence;
  session: Session1;
  type: Type6;
  version: Version54;
}
export interface Tasmota {
  firmware?: TasmotaFirmware;
  friendly_names?: FriendlyNames;
  module?: Module1;
  network?: TasmotaNetwork;
  wifi?: TasmotaWifi;
  [k: string]: unknown;
}
export interface TasmotaFirmware {
  build_date: BuildDate2;
  core: Core1;
  sdk: Sdk1;
  version: Version55;
  [k: string]: unknown;
}
export interface TasmotaNetwork {
  hostname: Hostname5;
  ip_address: IpAddress5;
  mac_address: MacAddress8;
  [k: string]: unknown;
}
export interface TasmotaWifi {
  bssid?: Bssid1;
  ssid: Ssid2;
  [k: string]: unknown;
}
export interface Telnet {
  do: Do;
  dont: Dont;
  will: Will;
  wont: Wont;
}
export interface Tibia {
  map?: Map2;
  monsters?: Monsters;
  motd?: Motd;
  npcs?: Npcs;
  owner?: Owner1;
  players?: Players1;
  rates?: Rates;
  serverinfo?: Serverinfo;
}
export interface Map2 {
  [k: string]: unknown;
}
export interface Monsters {
  [k: string]: unknown;
}
export interface Motd {
  [k: string]: unknown;
}
export interface Npcs {
  [k: string]: unknown;
}
export interface Owner1 {
  [k: string]: unknown;
}
export interface Players1 {
  [k: string]: unknown;
}
export interface Rates {
  [k: string]: unknown;
}
export interface Serverinfo {
  [k: string]: unknown;
}
export interface TilginABHomeGateway {
  product_name?: ProductName3;
  software_family?: SoftwareFamily;
  software_revision?: SoftwareRevision;
  [k: string]: unknown;
}
export interface TpLinkKasa {
  alias: Alias;
  dev_name: DevName;
  device_id: DeviceId3;
  fw_id?: FwId;
  hw_id: HwId;
  hw_ver: HwVer;
  latitude: Latitude1;
  longitude: Longitude1;
  mac_address: MacAddress9;
  model: Model7;
  oem_id: OemId;
  sw_ver: SwVer;
  type: Type7;
}
export interface TraneTracerSc {
  equipments?: Equipments;
  hardware_serial_number?: HardwareSerialNumber;
  hardware_type?: HardwareType;
  kernel_version?: KernelVersion1;
  product_name?: ProductName4;
  product_version?: ProductVersion1;
  server_boot_time?: ServerBootTime;
  server_name?: ServerName5;
  server_time?: ServerTime;
  vendor_name?: VendorName;
  [k: string]: unknown;
}
export interface TraneTracerScEquipment {
  device_name?: DeviceName3;
  display_name?: DisplayName;
  equipment_family?: EquipmentFamily;
  equipment_uri?: EquipmentUri;
  is_offline?: IsOffline;
  role_document?: RoleDocument;
  [k: string]: unknown;
}
export interface Ubiquiti {
  hostname?: Hostname6;
  ip?: Ip8;
  ip_alt?: IpAlt;
  mac?: Mac6;
  mac_alt?: MacAlt;
  product?: Product4;
  version?: Version56;
}
export interface UnitronicsPcom {
  hardware_version: HardwareVersion3;
  model: Model8;
  os_build: OsBuild1;
  os_version: OsVersion2;
  plc_name?: PlcName;
  plc_unique_id: PlcUniqueId;
  uid_master: UidMaster;
}
export interface Upnp {
  device_type?: DeviceType3;
  friendly_name?: FriendlyName2;
  manufacturer?: Manufacturer2;
  manufacturer_url?: ManufacturerUrl;
  model_description?: ModelDescription1;
  model_name?: ModelName7;
  model_number?: ModelNumber1;
  model_url?: ModelUrl;
  presentation_url?: PresentationUrl;
  serial_number?: SerialNumber9;
  services?: Services4;
  sub_devices?: SubDevices;
  udn?: Udn1;
  upc?: Upc;
}
export interface UpnpService {
  control_url?: ControlUrl;
  event_sub_url?: EventSubUrl;
  scpdurl?: Scpdurl;
  service_id?: ServiceId;
  service_type?: ServiceType;
  [k: string]: unknown;
}
export interface Vault {
  cluster_id?: ClusterId;
  cluster_name?: ClusterName;
  initialized?: Initialized;
  performance_standby?: PerformanceStandby;
  replication_dr_mode?: ReplicationDrMode;
  replication_performance_mode?: ReplicationPerformanceMode;
  sealed?: Sealed;
  server_time_utc?: ServerTimeUtc;
  standby?: Standby;
  version?: Version57;
  last_wal?: LastWal;
  license?: VaultLicense;
}
export interface VaultLicense {
  terminated?: Terminated;
  state?: State4;
  expiry_time?: ExpiryTime;
}
export interface VertxDoor {
  firmware_date: FirmwareDate1;
  firmware_version: FirmwareVersion5;
  internal_ip: InternalIp;
  mac: Mac7;
  name: Name32;
  type: Type8;
}
export interface Vespa {
  meta?: VespaMeta;
  config?: Config;
  servers?: Servers;
}
export interface VespaMeta {
  name?: Name33;
  generation?: Generation;
  timestamp?: Timestamp6;
  user?: User;
  checksum?: Checksum2;
  date?: Date1;
  path?: Path;
}
export interface Config {
  [k: string]: unknown;
}
export interface VespaServer {
  id?: Id7;
  bundle?: Bundle;
  class?: Class;
}
export interface Vmware {
  api_type?: ApiType;
  api_version?: ApiVersion2;
  build?: Build5;
  full_name?: FullName;
  instance_uuid?: InstanceUuid;
  license_product_name?: LicenseProductName;
  license_product_version?: LicenseProductVersion;
  locale_build?: LocaleBuild;
  locale_version?: LocaleVersion;
  name?: Name34;
  os_type?: OsType1;
  product_line_id?: ProductLineId;
  vendor?: Vendor5;
  version?: Version58;
  [k: string]: unknown;
}
export interface Vnc {
  geometry?: Geometry;
  protocol_version: ProtocolVersion2;
  security_types?: SecurityTypes;
  server_name?: ServerName6;
}
export interface SecurityTypes {
  [k: string]: string;
}
export interface WindowsExporter {
  windows_exporter_build_info?: WindowsExporterBuildInfo;
  windows_os_info?: WindowsOsInfo;
  windows_cs_hostname?: WindowsCsHostname;
}
export interface WindowsExporterBuildInfo {
  [k: string]: string;
}
export interface WindowsOsInfo {
  [k: string]: string;
}
export interface WindowsCsHostname {
  [k: string]: string;
}
export interface XiaomiMiio {
  device_id: DeviceId4;
  token: Token;
  [k: string]: unknown;
}
export interface Yeelight {
  firmware_version: FirmwareVersion6;
  model: Model9;
  [k: string]: unknown;
}
