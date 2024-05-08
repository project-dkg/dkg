// Copyright (C) 2024 Maxim [maxirmx] Samsonov (www.sw.consulting)
// All rights reserved.
// This file is a part of dkg applcation
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 1. Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
// TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS
// BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

using dkg.group;
using dkg.poly;
using dkg.share;
using dkg.util;
using DkgNodeApi;
using Google.Protobuf;
using Grpc.Core;
using System.Text;
using static DkgNodeApi.DkgNode;

namespace dkg.sample
{
    // Конфигурация узла (он же "node", "участник")
    class DkgNodeConfig
    {
        // Host:Port gRPC сервера этого узла
        public int Port;
        public string Host = "localhost";

        // Name просто для красоты
        public string Name() { return $"{{Dkg node {Host}:{Port}}}"; }

        // Если SendTo -  валидный индекс в массиве конфигураций узлов, то этот узел будет посылать сообщение узлу с индексом SendTo
        // "Сообщение" - это сообщение, зашифрованное распределённыим публичным ключом, если его удастся вычислить
        public int SendTo = -1;

        public bool IsMisbehaving = false;
    }

    // Узел
    // Создаёт instance gRPC сервера (class DkgNodeServer)
    // и gRPC клиента (это просто отдельный поток TheThread)
    // В TheThread реализована незатейливая логика этого примера
    class DkgNode
    {
        internal int Index { get; }
        internal int Port { get;  }
        internal string Host { get;  }
        internal int SendTo { get; }
        internal bool IsMisbehaving { get; } 
        internal Server GRpcServer { get; }
        internal DkgNodeServer DkgNodeSrv { get; }
        internal DkgNodeConfig[] Configs { get; } = [];

        // gRPC клиенты "в сторону" других участников
        // включая самого себя, чтобы было меньше if'ов
        internal Channel[] Channels { get; set; } = [];
        internal DkgNodeClient[] Clients { get; set; } = [];

        // Публичныке ключи других участников
        internal IPoint[] PublicKeys { get; set; } = [];

        internal Thread TheThread { get; set; }
        internal bool IsRunning { get; set; } = true;
        internal IGroup G { get; }

        public DkgNode (DkgNodeConfig[] configs, int index)
        {
            G = new Secp256k1Group();

            Index = index;
            Configs = configs;
            Port = configs[index].Port;
            Host = configs[index].Host;
            SendTo = configs[index].SendTo;
            IsMisbehaving = configs[index].IsMisbehaving;

            DkgNodeSrv = new DkgNodeServer(configs[index].Name(), G);

            GRpcServer = new Server
            {
                Services = { BindService(DkgNodeSrv) },
                Ports = { new ServerPort(Host, Port, ServerCredentials.Insecure) }
            };

            // gRPC клиент и драйвер всего процесса
            TheThread = new Thread(() =>
            {
                Channels = new Channel[Configs.Length];
                Clients = new DkgNodeClient[Configs.Length];
                for (int j = 0; j < Configs.Length; j++)
                {
                    Channels[j] = new($"{Configs[j].Host}:{Configs[j].Port}", ChannelCredentials.Insecure);
                    Clients[j] = new DkgNodeClient(Channels[j]);
                }

                Console.WriteLine($"Node at {Index} is up");

                // Таймаут, который используется в точках синхронизации вместо синхронизации
                int syncTimeout = Math.Max(1000, Configs.Length * 500);

                PublicKeys = new IPoint[Configs.Length];

                // Пороговое значение для верификации ключа, то есть сколько нужно валидных commitment'ов
                // Алгоритм Шамира допускает минимальное значение = N/2+1, где N - количество участников, но мы сделаем N. 
                // Сделаем N-1, так чтобы 1 неадекватная нода позволяла расшифровать сообщение, а две - нет.
                int threshold = PublicKeys.Length-1;

                // 1. Собираем публичные ключи со всех участников
                //    Тут, конечно, упрощение. Предполагается, что все ответят без ошибкт
                //    В промышленном варианте список участников, который у нас есть - это список желательных участников
                //    В этом уикле нужно сформировать список реальных кчастников, то есть тех, где gRPC end point хотя бы
                //    откликается
                for (int j = 0; j < Configs.Length; j++)
                {
                    if (Index == j)
                    {
                        PublicKeys[j] = DkgNodeSrv.PublicKey;
                        // Console.WriteLine($"Used own public key at node {Index}: {PublicKeys[j]}");
                    }
                    else
                    {
                        byte[] pkb = [];
                        var pk = Clients[j].GetPublicKey(new PublicKeyRequest());
                        if (pk != null)
                        {
                            pkb = pk.Data.ToByteArray();
                        }
                        if (pkb.Length != 0)
                        {
                            PublicKeys[j] = G.Point().SetBytes(pkb);
                            // Console.WriteLine($"Got public key of node {j} at node {Index}: {PublicKeys[j]}");
                        }
                        else
                        {
                            // См. комментарий выше
                            // PubliсKeys[j] = null  не позволит инициализировать узел
                            // Можно перестроить список участников, можно использовать "левый"
                            // Для демо считаем это фатальной ошибкой
                            Console.WriteLine($"FATAL ERROR FOR NODE {Index}: failed to get public key of node {j}");
                            IsRunning = false;
                        }
                    }
                }
                // Дадим время всем другим узлам обменяться публичными ключами
                // Можно добавить точку синхронизации, то есть отдельным gRPC вызовом опрашивать вскх участников дошли ли они до этой точки,
                // но тогда возникает вопром, что делать с теми кто до неё не доходит "никогда" (в смысле "достаточно быстро")
                Console.WriteLine($"Node at {Index} has collected public keys. Sleeping for {syncTimeout} ms");
                Thread.Sleep(syncTimeout);

                // Здесь будут distributed deals (не знаю, как перевести), предложенные этим узлом другим узлам
                // <индекс другого узла> --> наш deal для другого узла              
                Dictionary<int, DistDeal> deals = [];


                // 2. Создаём генератор/обработчик распределённого ключа для этого узла
                //    Это будет DkgNode.Dkg.  Он создаётся уровнем ниже, чтобы быть доступным как из gRPC клиента (этот объект),
                //    так и из сервера (DkgNode)

                if (IsRunning)
                {
                    try
                    {
                        DkgNodeSrv.Dkg = DistKeyGenerator.CreateDistKeyGenerator(G, DkgNodeSrv.PrivateKey, PublicKeys, threshold) ??
                              throw new Exception($"Could not create distributed key generator/handler for node {Index}");
                        deals = DkgNodeSrv.Dkg.GetDistDeals() ??
                                throw new Exception($"Could not get a list of deals for node {Index}");
                    }
                    // Исключение может быть явно созданное выше, а может "выпасть" из DistKeyGenerator 
                    // Ошибки здесь все фатальны
                    catch (Exception ex)
                    {
                        Console.WriteLine($"FATAL ERROR FOR NODE {Index}: {ex.Message}");
                        IsRunning = false;
                    }
                    Console.WriteLine($"Node at {Index} has created its deals");
                }

                DistKeyShare? distrKey = null;
                IPoint? distrPublicKey = null;

                // 3. Разошём наши "предложения" другим узлам
                //    В ответ мы ожидаем distributed response, который мы для начала сохраним 

                if (IsRunning)
                {
                    List<DistResponse> responses = new(deals.Count);
                    foreach (var (i, deal) in deals)
                    {
                        // Console.WriteLine($"Querying from {Index} to process for node {i}");

                        byte[] rspb = [];
                        // Самому себе тоже пошлём, хотя можно вызвать локально 
                        // if (Index == i) try { response = DkgNode.Dkg!.ProcessDeal(response) } catch { }
                        var rb = Clients[i].ProcessDeal(new ProcessDealRequest { Data = ByteString.CopyFrom(deal.GetBytes()) });
                        if (rb != null)
                        {
                            rspb = rb.Data.ToByteArray();
                        }
                        if (rspb.Length != 0)
                        {
                            DistResponse response = new();
                            response.SetBytes(rspb);
                            responses.Add(response);
                        }
                        else
                        {
                            // На этом этапе ошибка не является фатальной
                            // Просто у нас или получится или не получится достаточное количество commitment'ов
                            // См. комментариё выше про Threshold
                            Console.WriteLine($"Failed to get response from node {i} at node {Index}");
                        }
                    }

                    // Тут опять точка синхронизации
                    // Участник должен сперва получить deal, а только потом response'ы для этого deal
                    // В противном случае response будет проигнорирован
                    // Можно передать ошибку через gRPC, анализировать в цикле выше и вызывать ProcessResponse повторно.
                    // Однако, опять вопрос с теми, кто не ответит никогда.
                    Console.WriteLine($"Node at {Index} has distributed its deals. Sleeping for {syncTimeout} ms");
                    Thread.Sleep(syncTimeout);

                    if (!IsMisbehaving)
                    {
                        foreach (var response in responses)
                        {
                            for (int i = 0; i < PublicKeys.Length; i++)
                            {
                                // Самому себе тоже пошлём, хотя можно вызвать локально 
                                // if (Index == i) try { DkgNode.Dkg!.ProcessResponse(response) } catch { }
                                Clients[i].ProcessResponse(new ProcessResponseRequest { Data = ByteString.CopyFrom(response.GetBytes()) });
                            }
                        }

                        // И ещё одна точка синхронизации
                        // Теперь мы ждём, пока все обменяются responsе'ами
                        Console.WriteLine($"Node at {Index} has distributed its responses. Sleeping for {syncTimeout} ms");
                        Thread.Sleep(syncTimeout);
                    }
                    else
                    {
                        Console.WriteLine($"Node at {Index} is misbehaving");
                    }

                    DkgNodeSrv.Dkg!.SetTimeout();

                    // Обрадуемся тому, что нас признали достойными :)
                    bool crt = DkgNodeSrv.Dkg!.ThresholdCertified();
                    string certified = crt ? "" : "not ";
                    Console.WriteLine($"Node at {Index} is {certified}certified");

                    if (crt)
                    {
                        // Методы ниже безопасно вызывать, только если ThresholdCertified() вернул true
                        distrKey = DkgNodeSrv.Dkg!.DistKeyShare();
                        DkgNodeSrv.SecretShare = distrKey.PriShare();
                        distrPublicKey = distrKey.Public();
                    }
                    
                    IsRunning = crt;
                }

                //  Если все условия совпали, пошлём сообщение другому узлу
                //  Нужно помнить, что тут применён "прямой" ElGamal на эллиптической кривой, то есть сообщение "вложено" в point
                //  Так можно зашифровать только 32 байта
                //  В реальной жизни применяю гибридный алгоритм, когда эти 32 байта - это ключ для симметричного алгоритма, которым 
                //  зашифровано само сообщение
                if (IsRunning && SendTo >= 0 && SendTo < Clients.Length)
                {
                    string message = $"Hello from node at {Index} :)";
                    var (C1, C2) = ECElGamalEncryption.Encrypt(G, distrPublicKey!, message);
                    Console.WriteLine($"Node at {Index} is sending message '{message}' to node at {SendTo}");
                    Clients[SendTo].SendMessage(new SendMessageRequest { 
                        C1 = ByteString.CopyFrom(C1.GetBytes()),
                        C2 = ByteString.CopyFrom(C2.GetBytes()),
                    });
                }

                // В этом цикле мы ждём входящего сообщения
                // Мы реализуем метод B, как он описан в файле "AnEndToEndExample.cs" тестового проекта, когда
                // каждый узел обеспечтвает частичную расшифровку сообщения
                // В тестовом пример есть комментарии, сравнение с другими методами и тестовый пример проще понять, потому что он синхронный, на общих массивах
                while (IsRunning)
                {
                    Thread.Sleep(100);

                    IPoint C1 = G.Point();
                    IPoint C2 = G.Point();
                    bool hasMessage = false;

                    lock (DkgNodeSrv.messageLock)
                    {
                        if (DkgNodeSrv.HasMessage)
                        {
                            C1 = DkgNodeSrv.C1;
                            C2 = DkgNodeSrv.C2;
                            DkgNodeSrv.HasMessage = false;
                            hasMessage = true;
                        }
                    }
                    if (hasMessage)
                    {
                        Console.WriteLine($"Node at {Index} has received a message");
                        // Попытка расшифровать сообщение может закочиться исключением
                        // Например, если злонамеренно прислать в cipher точку не из используемой группы
                        try
                        {

                            var pubShares = new List<PubShare>();
                            for (int i = 0; i < PublicKeys.Length; i++)
                            {
                                // Самому себе тоже пошлём, хотя можно вызвать локально 
                                var rb = Clients[i].PartialDecrypt(new PartialDecryptRequest
                                {
                                    C1 = ByteString.CopyFrom(C1.GetBytes()),
                                    C2 = ByteString.CopyFrom(C2.GetBytes()),
                                });
                                byte[] rspb = [];
                                if (rb != null && rb.Partial != null)
                                {
                                    rspb = rb.Partial.ToByteArray();
                                }
                                if (rspb.Length != 0)
                                {
                                    var partial = G.Point();
                                    partial.SetBytes(rspb);
                                    pubShares.Add(new PubShare(i, partial));
                                    Console.WriteLine($"Node at {Index} has recieved partial decrypt from node at {i}");
                                }
                                else
                                {
                                    Console.WriteLine($"Node at {Index} failed to recieve partial decrypt from node at {i}");
                                }
                            }

                            var res = PubPoly.RecoverCommit(G, [.. pubShares], threshold, PublicKeys.Length);
                            string decryptedMessage = Encoding.UTF8.GetString(res.ExtractData());
                            Console.WriteLine($"The message decrypted by node at {Index}: '{decryptedMessage}'");
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"Мessage decryption has failed node at {Index}: {ex.Message}");
                        }
                        hasMessage = false;
                    }
                }

                //Console.WriteLine($"Terminating node {Index}");
                for (int j = 0; j < Configs.Length; j++)
                {
                    Channels[j].ShutdownAsync().Wait();
                }

                Console.WriteLine($"Node at {Index} is down");
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
            TheThread.Join();
        }

    }

    // gRPC сервер
    // Здесь "сложены" параметры узла, которые нужны и клиенту и серверу
    class DkgNodeServer : DkgNodeBase
    {
        private IGroup G { get; }
        internal string Name { get; }
        internal IScalar PrivateKey { get; }  // Публичный ключ этого узла
        internal IPoint PublicKey { get; }    // Приватный ключ этого узла  
        internal PriShare? SecretShare { get; set; } = null;

        public DistKeyGenerator? Dkg { get; set; } = null;

        // Защищает Dkg от параллельной обработки наскольких запросов
        internal readonly object dkgLock = new() { };

        // Защищает сообщение, с которым мы работаем
        internal readonly object messageLock = new() { };

        // Есть сообщение, с которым мы работаем
        // Нерасшифрованное входящее соообщение может быть только одно
        internal bool HasMessage { get; set; } = false;

        // Cipher
        internal IPoint C1 { get; set; }
        internal IPoint C2 { get; set; }
        public DkgNodeServer(string name, IGroup group)
        {
            G = group;
            C1 = G.Point();
            C2 = G.Point();
            Name = name;
            PrivateKey = G.Scalar();
            PublicKey = G.Base().Mul(PrivateKey);
        }

        // gRPC сервер реализует 4 метода
        //
        // Выдача публичного ключа
        // ProcessDeal
        // ProcessResponse
        // Прием сообщения
        // Частичная расшифровка
        public override Task<PublicKeyReply> GetPublicKey(PublicKeyRequest _, ServerCallContext context)
        {
            PublicKeyReply resp = new() { Data = ByteString.CopyFrom(PublicKey.GetBytes()) };
            return Task.FromResult(resp);
        }

        public override Task<ProcessDealReply> ProcessDeal(ProcessDealRequest deal, ServerCallContext context)
        {
            ProcessDealReply resp;

            DistDeal distDeal = new();
            distDeal.SetBytes(deal.Data.ToByteArray());

            lock (dkgLock)
            {
                ByteString data = ByteString.CopyFrom([]);
                if (Dkg != null)
                {
                    try
                    {
                        data = ByteString.CopyFrom(Dkg.ProcessDeal(distDeal).GetBytes());
                    }
                    catch (Exception ex)
                    {
                        // Ошибки на данном этапе не являются фатальными
                        // Если response'а нет, это просто значит, что в дальнейшую обработку ничего не уйдёт. 
                        Console.WriteLine($"{Name}: {ex.Message}");
                    }
                }

                resp = new ProcessDealReply { Data = data };
            }
            return Task.FromResult(resp);
        }

        public override Task<ProcessResponseReply> ProcessResponse(ProcessResponseRequest response, ServerCallContext context)
        {
            DistResponse distResponse = new();
            distResponse.SetBytes(response.Data.ToByteArray());

            lock (dkgLock)
            {
                ByteString data = ByteString.CopyFrom([]);
                if (Dkg != null)
                {
                    try
                    {
                        DistJustification? distJust = Dkg.ProcessResponse(distResponse);
                        if (distJust != null)
                            Console.WriteLine($"{Name}: justification !!!");
                        //    data = ByteString.CopyFrom(distJust.GetBytes());
                    }
                    catch (Exception ex)
                    {
                        // Ошибки на данном этапе не являются фатальными
                        // Если response не удалось обработать, это значит, что он не учитывается. Как будто и не было.
                        Console.WriteLine($"{Name}: {ex.Message}");
                    }
                }
            }
            return Task.FromResult(new ProcessResponseReply());
        }
        public override Task<SendMessageReply> SendMessage(SendMessageRequest response, ServerCallContext context)
        {
            string? error = null;
            var c1 = G.Point();
            var c2 = G.Point();

            try
            {
                c1.SetBytes(response.C1.ToByteArray());
                c2.SetBytes(response.C2.ToByteArray());
            }
            catch
            {
                error = "Invalid cipher received, discarded";
            }

            if (error == null)
            {
                lock (messageLock)
                {
                    if (!HasMessage)
                    {
                        C1 = c1;
                        C2 = c2;
                        HasMessage = true;
                    }
                    else
                    {
                        error = "Could not process a second message, discarded";
                    }
                }
            }
            if (error != null)
            {
                Console.WriteLine($"{Name}: {error}");
            }

            return Task.FromResult(new SendMessageReply());
        }
        public override Task<PartialDecryptReply> PartialDecrypt(PartialDecryptRequest response, ServerCallContext context)
        {
            var reply = new PartialDecryptReply();
            if (SecretShare == null)
            {
                Console.WriteLine($"{Name}: could not process partial decrypt request since SecretShare is not set");
            }
            else
            {
                try
                {
                    var c1 = G.Point();
                    var c2 = G.Point();

                    c1.SetBytes(response.C1.ToByteArray());
                    c2.SetBytes(response.C2.ToByteArray());

                    var S = c1.Mul(SecretShare!.V);
                    var partial = c2.Sub(S);
                    reply = new PartialDecryptReply{ 
                        Partial = ByteString.CopyFrom(partial.GetBytes()
                     )};

                }
                catch (Exception ex)
                {
                    Console.WriteLine($"{Name}: could not process partial decrypt request: {ex.Message}");
                }
            }
            return Task.FromResult(reply);
        }
    }
    public class Program
    {
        // Количество узлов
        const int nDkgNodes = 7;
        // Первый порт для gRPC серверов, то есть они будут на 50051, 50052, ...
        const int BasePort = 50051;

        internal static void runSample(DkgNodeConfig[] dkgConfigs, string prompt)
        {
            DkgNode[] dkgNodes = new DkgNode[nDkgNodes];

            Console.WriteLine(prompt);
            Console.ReadKey();
            Console.WriteLine("");

            for (int i = 0; i < nDkgNodes; i++)
            {
                dkgNodes[i] = new DkgNode(dkgConfigs, i);
            }

            for (int i = 0; i < nDkgNodes; i++)
            {
                dkgNodes[i].Start();
            }
            Thread.Sleep(Math.Max(1000, nDkgNodes * 500) * 5);
            for (int i = 0; i < nDkgNodes; i++)
            {
                dkgNodes[i].Shutdown();
            }
           
        }
        public static void Main(string[] _)
        {
            DkgNodeConfig[] dkgConfigs = new DkgNodeConfig[nDkgNodes];
                        for (int i = 0; i < nDkgNodes; i++)
            {
                dkgConfigs[i] = new DkgNodeConfig() { Port = BasePort + i };
            }

            // Кто кому посылает сообщения
            dkgConfigs[0].SendTo = 1;
            dkgConfigs[1].SendTo = 4;

            Console.WriteLine(" ==== Welcome ==== \n\n");

            runSample(dkgConfigs, "Press any key to run without misbehaving nodes ...");

            dkgConfigs[2].IsMisbehaving = true;
            runSample(dkgConfigs, "Press any key to run with a single misbehaving node ...");

            dkgConfigs[3].IsMisbehaving = true;
            runSample(dkgConfigs, "Press any key to run with two misbehaving nodes ...");

            Console.WriteLine("Press any key to finish ...");
            Console.ReadKey();
            Console.WriteLine("");

        }
    }
}