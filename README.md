# th360-iis-monitoreo (`IisMonitor`)

Herramienta de diagnóstico de larga duración (por defecto **72 horas / 3 días**) para servidores **Windows Server 2019** con **IIS (.NET Framework 4.5)** y trabajos en **Node.js**, diseñada para detectar bloqueos silenciosos (sitios colgados sin picos de CPU, RAM ni disco) y generar reportes en texto plano optimizados para análisis por agentes de IA.

## Qué monitorea y por qué

Cuando una aplicación IIS/.NET 4.5 se cuelga sin saturar CPU ni RAM, el cuello de botella suele estar en recursos bloqueantes o agotados:

| Capa | Qué recolecta | Qué problema detecta |
|---|---|---|
| **IIS (`Microsoft.Web.Administration` + fallback WMI)** | AppPools, PIDs de `w3wp.exe` y peticiones activas (`WorkerProcess.GetRequests(0)` con URL, verbo, módulo y tiempo transcurrido) | Peticiones colgadas (*hung requests*), bloqueos en el pipeline y reciclajes/caídas inesperadas de AppPools |
| **ADO.NET SqlClient (PerfCounters)** | `.NET Data Provider for SqlServer`: `NumberOfPooledConnections`, `NumberOfReclaimedConnections`, `Hard/SoftConnectsPerSecond`, `NumberOfActiveConnections`, etc. | Agotamiento del pool de conexiones (límite por defecto = 100) y fugas de conexiones no cerradas reclamadas por el GC |
| **Sockets TCP (`iphlpapi.dll` IPv4/IPv6)** | Tabla TCP por PID (`GetExtendedTcpTable`), filtrando puertos de base de datos (`1433` por defecto) y estados `ESTABLISHED`, `CLOSE_WAIT`, `TIME_WAIT` | Fugas de conexiones a BD (`CLOSE_WAIT`), saturación de sockets `ESTABLISHED` y *churn* en `TIME_WAIT` |
| **ASP.NET / HTTP.sys / CLR (PerfCounters)** | Colas de peticiones (`ASP.NET v4.0.30319`, `HTTP Service Request Queues`), contención de hilos, excepciones/s y GC | Acumulación de cola, contención de ThreadPool/locks y tormentas de excepciones |
| **Procesos Node.js (`node.exe` + WMI)** | PID, script/línea de comandos, uptime, RAM, delta de CPU y sockets TCP abiertos hacia BD | Jobs *zombie* o colgados reteniendo conexiones a la base de datos |
| **Windows Event Log (`Application` y `System`)** | Lectura incremental de advertencias/errores de `ASP.NET`, `.NET Runtime`, `WAS`, `W3SVC`, `IIS`, `HTTP`, `SqlClient` | Timeouts del pool de SQL (`max pool size was reached`) y eventos de reciclaje/crash de WAS (`5002`, `5009`, `5011`, `5074-5080`, `5139`) |

## Prerrequisitos

- **En el servidor destino (Windows Server 2019):**
  - Ejecutar como **Administrador** (requerido para `Microsoft.Web.Administration`, `WorkerProcess.GetRequests(0)`, líneas de comandos WMI de otros usuarios y lectura completa de Event Logs).
  - Si se publica como *self-contained* (`win-x64`), **no requiere instalar .NET 10** en el servidor.
- **Para compilar/publicar (estación de desarrollo):**
  - .NET 10 SDK (`net10.0-windows`).

## Compilación, pruebas y publicación para Windows Server 2019

```powershell
# Compilar y ejecutar pruebas unitarias
dotnet build IisMonitor.sln
dotnet test IisMonitor.sln

# Publicar ejecutable self-contained (archivo único) para Windows Server 2019 (x64)
dotnet publish src/IisMonitor.Console/IisMonitor.Console.csproj `
  -c Release `
  -r win-x64 `
  --self-contained true `
  -p:PublishSingleFile=true `
  -p:IncludeNativeLibrariesForSelfExtract=true `
  -o ./publish/win-x64
```

Copie el contenido de `./publish/win-x64` (`IisMonitor.exe` y `appsettings.json`) al servidor destino (por ejemplo, `C:\Tools\IisMonitor\`).

## Configuración (`appsettings.json` y CLI)

Todos los umbrales y parámetros se configuran en `appsettings.json` y pueden sobreescribirse por línea de comandos:

| Flag CLI | Descripción | Valor por defecto |
|---|---|---|
| `--duration-hours <n>` | Duración total en horas | `72` |
| `--duration-seconds <n>` | Duración total en segundos (sobreescribe horas; útil para pruebas) | — |
| `--interval-seconds <n>` | Intervalo de muestreo en segundos | `15` |
| `--checkpoint-minutes <n>` | Frecuencia de actualización del resumen ejecutivo | `60` |
| `--output <ruta>` | Carpeta de salida de reportes | `./monitor-output` |
| `--db-ports <p1,p2>` | Puertos TCP de base de datos a vigilar | `1433` |
| `--app-pools <a1,a2>` | Filtro opcional de AppPools (vacío = todos) | todos |
| `--once` | Toma una única muestra y finaliza | `false` |

## Ejecución durante 3 días (72 horas)

### Opción 1: Consola interactiva (como Administrador)

```powershell
cd C:\Tools\IisMonitor
.\IisMonitor.exe --duration-hours 72 --interval-seconds 15 --output C:\Logs\IisMonitor_Run1
```

Puede detenerlo en cualquier momento con `Ctrl+C`: el proceso realiza un cierre limpio y escribe el `00_AI_EXECUTIVE_SUMMARY.txt` final antes de salir.

### Opción 2: Tarea Programada (recomendado para no depender de una sesión RDP)

```powershell
$action = New-ScheduledTaskAction `
  -Execute "C:\Tools\IisMonitor\IisMonitor.exe" `
  -Argument "--duration-hours 72 --interval-seconds 15 --output C:\Logs\IisMonitor_Run1" `
  -WorkingDirectory "C:\Tools\IisMonitor"

$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 74) -AllowStartIfOnBatteries

Register-ScheduledTask -TaskName "TH360-IisMonitor-72h" -Action $action -Principal $principal -Settings $settings
Start-ScheduledTask -TaskName "TH360-IisMonitor-72h"
```

## Nota sobre `NumberOfActiveConnections` en .NET Framework 4.5

Por defecto en .NET Framework 4.5, el contador `NumberOfActiveConnections` (y `NumberOfFreeConnections`) de `.NET Data Provider for SqlServer` viene deshabilitado para evitar sobrecarga. `IisMonitor` lo detecta automáticamente y continúa funcionando usando `NumberOfPooledConnections`, `NumberOfReclaimedConnections` y los sockets TCP reales por PID.

Si desea habilitar `NumberOfActiveConnections` (requiere reciclar los AppPools o reiniciar IIS), agregue en `machine.config` (x64 y x86, en `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\machine.config`):

```xml
<system.diagnostics>
  <switches>
    <add name="ConnectionPoolPerformanceCounterDetail" value="4" />
  </switches>
</system.diagnostics>
```

## Archivos generados y cómo analizarlos con agentes de IA

La carpeta de salida contendrá únicamente archivos de texto plano estructurados:

1. `00_AI_EXECUTIVE_SUMMARY.txt` — **Empiece aquí.** Resumen ejecutivo compacto (actualizado cada hora y al finalizar) con hipótesis de causa raíz ordenadas por evidencia, matriz de salud por AppPool, resumen de jobs Node.js y top 20 ventanas de incidentes con timestamps UTC.
2. `01_INCIDENTS_AND_ANOMALIES.jsonl` — Flujo cronológico de anomalías detectadas (una línea JSON por evento).
3. `02_TIMELINE_METRICS_YYYY-MM-DD.jsonl` — Métricas detalladas rotadas diariamente en UTC.
4. `03_EVENTLOG_FINDINGS.jsonl` — Advertencias y errores filtrados de Windows Event Log.

**Flujo recomendado para agentes de IA:** entregue primero `00_AI_EXECUTIVE_SUMMARY.txt` al agente; a partir de las ventanas de incidentes (`[INC-001] ...`) y sus timestamps UTC, el agente puede inspeccionar líneas específicas en `01_INCIDENTS_AND_ANOMALIES.jsonl`, `02_TIMELINE_METRICS_*.jsonl` y `03_EVENTLOG_FINDINGS.jsonl` sin saturar su ventana de contexto.
