using IisMonitor.Collectors;
using IisMonitor.Domain;

namespace IisMonitor.Tests;

public sealed class TcpSocketGroupingTests
{
    [Fact]
    public void SummarizeConnections_GroupsByPid_And_HighlightsDbPorts()
    {
        var connections = new List<RawTcpConnection>
        {
            new(100, "10.0.0.1", 50001, "10.0.0.50", 1433, "ESTABLISHED", false),
            new(100, "10.0.0.1", 50002, "10.0.0.50", 1433, "ESTABLISHED", false),
            new(100, "10.0.0.1", 50003, "10.0.0.50", 1433, "CLOSE_WAIT", false),
            new(100, "10.0.0.1", 50004, "10.0.0.99", 443, "ESTABLISHED", false),
            new(200, "10.0.0.1", 51001, "10.0.0.51", 1433, "TIME_WAIT", false),
            new(200, "::1", 51002, "::1", 5432, "ESTABLISHED", true)
        };

        var result = TcpSocketCollector.SummarizeConnections(connections, new HashSet<int> { 1433, 5432 });

        Assert.Equal(6, result.TotalSystemSockets);
        Assert.Equal(1, result.TotalSystemTimeWait);
        Assert.Equal(1, result.TotalSystemCloseWait);
        Assert.Equal(3, result.TotalDbEstablished);
        Assert.Equal(1, result.TotalDbCloseWait);

        var pid100 = result.ByPid[100];
        Assert.Equal(4, pid100.TotalSockets);
        Assert.Equal(3, pid100.DbTotalSockets);
        Assert.Equal(2, pid100.DbEstablished);
        Assert.Equal(1, pid100.DbCloseWait);
        Assert.Single(pid100.TopDbEndpoints);
        Assert.Equal("10.0.0.50:1433", pid100.TopDbEndpoints[0].RemoteEndpoint);

        var pid200 = result.ByPid[200];
        Assert.Equal(2, pid200.DbTotalSockets);
        Assert.Equal(1, pid200.DbEstablished);
        Assert.Equal(1, pid200.DbTimeWait);
    }

    [Fact]
    public void ConvertNetworkPort_ConvertsBigEndianCorrectly()
    {
        // 1433 = 0x0599 -> network byte order uint low 16 bits = 0x9905 = 39173
        Assert.Equal(1433, TcpSocketCollector.ConvertNetworkPort(0x9905));
        // 443 = 0x01BB -> network byte order = 0xBB01
        Assert.Equal(443, TcpSocketCollector.ConvertNetworkPort(0xBB01));
    }

    [Fact]
    public void ParseAppPoolAndAdoNetPidHelpers_WorkCorrectly()
    {
        Assert.Equal("MyAppPool", IisWorkerProcessCollector.ParseAppPoolFromCommandLine(@"c:\windows\system32\inetsrv\w3wp.exe -ap ""MyAppPool"" -v ""v4.0"""));
        Assert.Equal("SimplePool", IisWorkerProcessCollector.ParseAppPoolFromCommandLine(@"w3wp.exe -ap SimplePool -a \\.\pipe\iisipm"));
        Assert.Equal(4512, AdoNetPoolCollector.ParsePidFromInstanceName("w3wp[4512]"));
        Assert.Equal(9876, AdoNetPoolCollector.ParsePidFromInstanceName("_lm_w3svc_1_root[9876]"));
        Assert.Equal("worker.js", NodeProcessCollector.ExtractJobLabel(@"node.exe --max-old-space-size=512 C:\jobs\worker.js --env prod", 123));
    }
}
