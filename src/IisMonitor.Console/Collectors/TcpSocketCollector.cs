using System.Net;
using System.Runtime.InteropServices;
using IisMonitor.Abstractions;
using IisMonitor.Domain;

namespace IisMonitor.Collectors;

public sealed class TcpSocketCollector : ITcpSocketCollector
{
    private const int AfInet = 2;
    private const int AfInet6 = 23;
    private const uint ErrorInsufficientBuffer = 122;
    private const uint NoError = 0;

    private enum TcpTableClass
    {
        TcpTableOwnerPidAll = 5
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcpRowOwnerPid
    {
        public uint State;
        public uint LocalAddr;
        public uint LocalPort;
        public uint RemoteAddr;
        public uint RemotePort;
        public uint OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcp6RowOwnerPid
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] LocalAddr;
        public uint LocalScopeId;
        public uint LocalPort;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] RemoteAddr;
        public uint RemoteScopeId;
        public uint RemotePort;
        public uint State;
        public uint OwningPid;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable,
        ref int dwOutBufLen,
        [MarshalAs(UnmanagedType.Bool)] bool sort,
        int ipVersion,
        TcpTableClass tblClass,
        uint reserved);

    public TcpCollectionResult Collect(IReadOnlySet<int> dbPorts)
    {
        var warnings = new List<string>();
        var connections = new List<RawTcpConnection>();

        try
        {
            connections.AddRange(ReadIpv4Table());
        }
        catch (Exception ex)
        {
            warnings.Add($"TCP IPv4 table read failed: {ex.Message}");
        }

        try
        {
            connections.AddRange(ReadIpv6Table());
        }
        catch (Exception ex)
        {
            warnings.Add($"TCP IPv6 table read failed: {ex.Message}");
        }

        return SummarizeConnections(connections, dbPorts, warnings);
    }

    public static TcpCollectionResult SummarizeConnections(
        IReadOnlyList<RawTcpConnection> connections,
        IReadOnlySet<int> dbPorts,
        IReadOnlyList<string>? warnings = null)
    {
        var byPidMutable = new Dictionary<int, PidAccumulator>();
        int totalTimeWait = 0;
        int totalCloseWait = 0;
        int totalDbEstablished = 0;
        int totalDbCloseWait = 0;

        foreach (var conn in connections)
        {
            if (conn.State == "TIME_WAIT") totalTimeWait++;
            if (conn.State == "CLOSE_WAIT") totalCloseWait++;

            bool isDb = dbPorts.Contains(conn.RemotePort);
            if (isDb)
            {
                if (conn.State == "ESTABLISHED") totalDbEstablished++;
                if (conn.State == "CLOSE_WAIT") totalDbCloseWait++;
            }

            if (!byPidMutable.TryGetValue(conn.Pid, out var acc))
            {
                acc = new PidAccumulator(conn.Pid);
                byPidMutable[conn.Pid] = acc;
            }

            acc.Add(conn, isDb);
        }

        var resultByPid = new Dictionary<int, PidTcpSocketSummary>(byPidMutable.Count);
        foreach (var (pid, acc) in byPidMutable)
        {
            resultByPid[pid] = acc.ToSummary();
        }

        return new TcpCollectionResult(
            ByPid: resultByPid,
            TotalSystemSockets: connections.Count,
            TotalSystemTimeWait: totalTimeWait,
            TotalSystemCloseWait: totalCloseWait,
            TotalDbEstablished: totalDbEstablished,
            TotalDbCloseWait: totalDbCloseWait,
            Warnings: warnings ?? []);
    }

    private static List<RawTcpConnection> ReadIpv4Table()
    {
        var list = new List<RawTcpConnection>();
        int bufferSize = 0;
        uint status = GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, false, AfInet, TcpTableClass.TcpTableOwnerPidAll, 0);
        if (status != ErrorInsufficientBuffer && status != NoError)
        {
            throw new InvalidOperationException($"GetExtendedTcpTable(IPv4) sizing returned {status}");
        }

        for (int attempt = 0; attempt < 3; attempt++)
        {
            int allocSize = Math.Max(bufferSize + 4096, 4096);
            IntPtr buffer = Marshal.AllocHGlobal(allocSize);
            try
            {
                int currentSize = allocSize;
                status = GetExtendedTcpTable(buffer, ref currentSize, false, AfInet, TcpTableClass.TcpTableOwnerPidAll, 0);
                if (status == ErrorInsufficientBuffer)
                {
                    bufferSize = currentSize;
                    continue;
                }

                if (status != NoError)
                {
                    throw new InvalidOperationException($"GetExtendedTcpTable(IPv4) returned {status}");
                }

                int rowCount = Marshal.ReadInt32(buffer);
                int rowSize = Marshal.SizeOf<MibTcpRowOwnerPid>();
                IntPtr rowPtr = IntPtr.Add(buffer, sizeof(int));

                for (int i = 0; i < rowCount; i++)
                {
                    var row = Marshal.PtrToStructure<MibTcpRowOwnerPid>(rowPtr);
                    list.Add(new RawTcpConnection(
                        Pid: unchecked((int)row.OwningPid),
                        LocalAddress: new IPAddress(row.LocalAddr).ToString(),
                        LocalPort: ConvertNetworkPort(row.LocalPort),
                        RemoteAddress: new IPAddress(row.RemoteAddr).ToString(),
                        RemotePort: ConvertNetworkPort(row.RemotePort),
                        State: MapTcpState(row.State),
                        IsIpv6: false));
                    rowPtr = IntPtr.Add(rowPtr, rowSize);
                }

                return list;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        return list;
    }

    private static List<RawTcpConnection> ReadIpv6Table()
    {
        var list = new List<RawTcpConnection>();
        int bufferSize = 0;
        uint status = GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, false, AfInet6, TcpTableClass.TcpTableOwnerPidAll, 0);
        if (status != ErrorInsufficientBuffer && status != NoError)
        {
            throw new InvalidOperationException($"GetExtendedTcpTable(IPv6) sizing returned {status}");
        }

        for (int attempt = 0; attempt < 3; attempt++)
        {
            int allocSize = Math.Max(bufferSize + 4096, 4096);
            IntPtr buffer = Marshal.AllocHGlobal(allocSize);
            try
            {
                int currentSize = allocSize;
                status = GetExtendedTcpTable(buffer, ref currentSize, false, AfInet6, TcpTableClass.TcpTableOwnerPidAll, 0);
                if (status == ErrorInsufficientBuffer)
                {
                    bufferSize = currentSize;
                    continue;
                }

                if (status != NoError)
                {
                    throw new InvalidOperationException($"GetExtendedTcpTable(IPv6) returned {status}");
                }

                int rowCount = Marshal.ReadInt32(buffer);
                int rowSize = Marshal.SizeOf<MibTcp6RowOwnerPid>();
                IntPtr rowPtr = IntPtr.Add(buffer, sizeof(int));

                for (int i = 0; i < rowCount; i++)
                {
                    var row = Marshal.PtrToStructure<MibTcp6RowOwnerPid>(rowPtr);
                    list.Add(new RawTcpConnection(
                        Pid: unchecked((int)row.OwningPid),
                        LocalAddress: new IPAddress(row.LocalAddr).ToString(),
                        LocalPort: ConvertNetworkPort(row.LocalPort),
                        RemoteAddress: new IPAddress(row.RemoteAddr).ToString(),
                        RemotePort: ConvertNetworkPort(row.RemotePort),
                        State: MapTcpState(row.State),
                        IsIpv6: true));
                    rowPtr = IntPtr.Add(rowPtr, rowSize);
                }

                return list;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        return list;
    }

    internal static int ConvertNetworkPort(uint networkPort) =>
        (int)(((networkPort & 0xFF) << 8) | ((networkPort >> 8) & 0xFF));

    internal static string MapTcpState(uint state) => state switch
    {
        1 => "CLOSED",
        2 => "LISTEN",
        3 => "SYN_SENT",
        4 => "SYN_RCVD",
        5 => "ESTABLISHED",
        6 => "FIN_WAIT1",
        7 => "FIN_WAIT2",
        8 => "CLOSE_WAIT",
        9 => "CLOSING",
        10 => "LAST_ACK",
        11 => "TIME_WAIT",
        12 => "DELETE_TCB",
        _ => $"UNKNOWN_{state}"
    };

    private sealed class PidAccumulator(int pid)
    {
        private readonly Dictionary<string, int> _stateCounts = new(StringComparer.Ordinal);
        private readonly Dictionary<string, EndpointAccumulator> _dbEndpoints = new(StringComparer.Ordinal);
        private int _totalSockets;
        private int _dbTotal;
        private int _dbEstablished;
        private int _dbCloseWait;
        private int _dbTimeWait;
        private int _dbSynSent;

        public void Add(RawTcpConnection conn, bool isDb)
        {
            _totalSockets++;
            _stateCounts[conn.State] = _stateCounts.TryGetValue(conn.State, out int count) ? count + 1 : 1;

            if (!isDb) return;

            _dbTotal++;
            switch (conn.State)
            {
                case "ESTABLISHED": _dbEstablished++; break;
                case "CLOSE_WAIT": _dbCloseWait++; break;
                case "TIME_WAIT": _dbTimeWait++; break;
                case "SYN_SENT": _dbSynSent++; break;
            }

            string endpoint = conn.IsIpv6
                ? $"[{conn.RemoteAddress}]:{conn.RemotePort}"
                : $"{conn.RemoteAddress}:{conn.RemotePort}";

            if (!_dbEndpoints.TryGetValue(endpoint, out var ep))
            {
                ep = new EndpointAccumulator(endpoint);
                _dbEndpoints[endpoint] = ep;
            }

            ep.Add(conn.State);
        }

        public PidTcpSocketSummary ToSummary()
        {
            var topEndpoints = _dbEndpoints.Values
                .OrderByDescending(e => e.Total)
                .Take(10)
                .Select(e => new RemoteEndpointCount(e.Endpoint, e.Total, e.Established, e.CloseWait, e.TimeWait))
                .ToList();

            return new PidTcpSocketSummary(
                Pid: pid,
                TotalSockets: _totalSockets,
                StateCounts: _stateCounts,
                DbTotalSockets: _dbTotal,
                DbEstablished: _dbEstablished,
                DbCloseWait: _dbCloseWait,
                DbTimeWait: _dbTimeWait,
                DbSynSent: _dbSynSent,
                TopDbEndpoints: topEndpoints);
        }
    }

    private sealed class EndpointAccumulator(string endpoint)
    {
        public string Endpoint { get; } = endpoint;
        public int Total { get; private set; }
        public int Established { get; private set; }
        public int CloseWait { get; private set; }
        public int TimeWait { get; private set; }

        public void Add(string state)
        {
            Total++;
            switch (state)
            {
                case "ESTABLISHED": Established++; break;
                case "CLOSE_WAIT": CloseWait++; break;
                case "TIME_WAIT": TimeWait++; break;
            }
        }
    }
}
