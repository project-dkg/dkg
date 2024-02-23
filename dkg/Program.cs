
// https://github.com/dedis/kyber/blob/master/share/dkg/pedersen/dkg.go

using dkg;
using dkg.group;
using dkg.share;

using DkgNodeApi;
using Google.Protobuf;
using Grpc.Core;
using static DkgNodeApi.DkgNode;
using static System.Runtime.InteropServices.JavaScript.JSType;
using HashAlgorithm = System.Security.Cryptography.HashAlgorithm;

namespace GrpcServer
{
    class DkgNodeConfig
    {
        public int Port;
        public string Host = "localhost";
        public string Name() { return $"{{Dkg node {Host}:{Port}}}"; }
    }
    class DkgNodeWrapper
    {
        internal int Index { get; set; }
        internal int Port { get; set; }
        internal string Host { get; set; }
        internal Server GRpcServer { get; set; }
        internal DkgNodeImpl DkgNode { get; set; }
        internal string Name() { return DkgNode.Name; }
        internal IPoint PublicKey() { return DkgNode.PublicKey; }
        internal IScalar PrivateKey() { return DkgNode.PrivateKey; }
        internal DkgNodeConfig[] Configs { get; set; } = [];
        internal Channel[] Channels = [];
        internal DkgNodeClient[] Clients = [];

        // Это те публичныке ключи, которые удалось собрать
        // (на  случай, если какие-то узлы не запущены/не доступны делаем Dictionary)
        internal Dictionary<int, IPoint> PublicKeys = [];

        internal Thread TheThread { get; set; }
        internal bool IsRunning = true;
        internal HashAlgorithm Hash;

        public DkgNodeWrapper (DkgNodeConfig[] configs, int index)
        {
            // !!! HashAlgorithm из System.Security.Cryptography не Thread Safe !!! 
            //                Его приходится "клепать" в каждом потоке
            Hash = System.Security.Cryptography.SHA256.Create();

            Index = index;
            Configs = configs;
            Port = configs[index].Port;
            Host = configs[index].Host;
            DkgNode = new DkgNodeImpl(configs[index].Name());

            GRpcServer = new Server
            {
                Services = { BindService(DkgNode) },
                Ports = { new ServerPort(Host, Port, ServerCredentials.Insecure) }
            };

            // Основная логика узла, вернее её прототип
            TheThread = new Thread(() =>
            {
                Channels = new Channel[Configs.Length];
                Clients = new DkgNodeClient[Configs.Length];
                for (int j = 0; j < Configs.Length; j++)
                {
                    Channels[j] = new($"{Configs[j].Host}:{Configs[j].Port}", ChannelCredentials.Insecure);
                    Clients[j] = new DkgNodeClient(Channels[j]);
                }

                Console.WriteLine($"{Name()} worker thread is up");

                PublicKeys = new Dictionary<int, IPoint>(Configs.Length);

                // 1. Собираем публичные ключи со всех узлов
                for (int j = 0; j < Configs.Length; j++)
                {
                    if (Index == j)
                    {
                        PublicKeys.Add(Index, PublicKey());
                    }
                    else
                    {
                        var pk = Clients[j].GetPublicKey(new PublicKeyRequest());
                        if (pk != null)
                        {
                            byte[] pkb = pk.Data.ToByteArray();
                            PublicKeys.Add(j, Suite.G.Base().SetBytes(pkb));
                            //Console.WriteLine($"Got public key of node {j} at node {Index}: {PublicKeys[j]}");
                        }
                        else
                        {
                            Console.WriteLine($"Failed to get public key of node {j} at node {Index}");
                        }
                    }
                }
                Thread.Sleep(1000);
                // 2. Создаём генератор/обработчик распределённого ключа для этого узла
                Dictionary<int, DistDeal>? deals = null;
                try
                {
                        DkgNode.Dkg = DistKeyGenerator.CreateDistKeyGenerator(Hash, PrivateKey(), [ ..PublicKeys.Values], PublicKeys.Count) ??
                              throw new Exception($"Could not create distributed key generator/handler for node {Index}");
                        deals = DkgNode.Dkg.GetDistDeals() ??
                                throw new Exception($"Could not get a list of deals for node {Index}");
                }
                catch(Exception ex)
                {
                    Console.WriteLine($"FATAL ERROR FOR NODE {Index}: {ex.Message}");
                    IsRunning = false;
                }

                if (IsRunning)
                {
                    foreach (var deal in deals!)
                    {
                        int i = deal.Key;
                        int j = PublicKeys.Keys.ElementAt(i);
                        Console.WriteLine($"Querying from {Index} to process for node {i} @{j}");

                        byte[] db = deal.Value.GetBytes();
                        Clients[j].ProcessDeal(new ProcessDealRequest { Data = ByteString.CopyFrom(db) });
                    }
                }
            
                while (IsRunning)
                {
                    Thread.Sleep(10);
                }

                Console.WriteLine($"Terminating node {Index}");
                for (int j = 0; j < Configs.Length; j++)
                {
                    Channels[j].ShutdownAsync().Wait();
                }

                // Console.WriteLine($"{Name()} worker thread is down");
            });

        }

        public void Start()
        {

            GRpcServer.Start();
            TheThread.Start();
        }

        public void Shutdown()
        {
            GRpcServer.ShutdownAsync().Wait();
            // Console.WriteLine($"{Name()} gRPC server has been stopped");
            IsRunning = false;
        }

    }

    class DkgNodeImpl : DkgNodeBase
    {
        internal string Name;
        internal IScalar PrivateKey { get; set; }
        internal IPoint PublicKey { get; set; }

        public DistKeyGenerator? Dkg = null;

        internal readonly object lockobject = new() { };

        public DkgNodeImpl(string name)
        {
            Name = name;
            PrivateKey = Suite.G.Scalar();
            PublicKey = Suite.G.Base().Mul(PrivateKey);
        }
        public override Task<PublicKeyResponse> GetPublicKey(PublicKeyRequest _, ServerCallContext context)
        {
            PublicKeyResponse resp = new() { Data = ByteString.CopyFrom(PublicKey.GetBytes()) };
            return Task.FromResult(resp);
        }

        public override Task<ProcessDealResponse> ProcessDeal(ProcessDealRequest deal, ServerCallContext context)
        {
            ProcessDealResponse resp;
            
            DistDeal distDeal = new();
            distDeal.SetBytes(deal.Data.ToByteArray());

            lock (lockobject)   // Защищаем Dkg от параллельной обработки наскольких запросов
            {
                ByteString data = ByteString.CopyFrom([]);
                if (Dkg != null)
                {
                    try
                    {
                        DistResponse distResp = Dkg.ProcessDeal(distDeal);
                        // byte[] respData = distResp.GetBytes();
                        //data = ByteString.CopyFrom(PublicKey.GetBytes());
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"{Name}: {ex.Message}");
                    }
                }

                resp = new ProcessDealResponse { Data = data };
            }
            return Task.FromResult(resp);
        }
    }

    public class Program
    {
        const int nDkgNodes = 7;
        const int BasePort = 50051;

        public static void Main(string[] args)
        {
            DkgNodeConfig[] dkgConfigs = new DkgNodeConfig[nDkgNodes];

            for (int i = 0; i < nDkgNodes; i++)
            {
                dkgConfigs[i] = new DkgNodeConfig() { Port = BasePort + i };
            }

            DkgNodeWrapper[] dkgNodes = new DkgNodeWrapper[nDkgNodes];
            for (int i = 0; i < nDkgNodes; i++)
            {
                dkgNodes[i] = new DkgNodeWrapper(dkgConfigs, i);
            }

            for (int i = 0; i < nDkgNodes; i++)
            {
                dkgNodes[i].Start();
            }

            Console.WriteLine("Press any key to finish...");
            Console.ReadKey();
            Console.WriteLine("");

            for (int i = 0; i < nDkgNodes; i++)
            {
                dkgNodes[i].Shutdown();
            }

        }
    }
}