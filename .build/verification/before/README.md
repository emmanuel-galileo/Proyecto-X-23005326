# Proyecto #02: Herramienta de Diagnóstico Traceroute (`my_traceroute`)

**Materia / Asignación**: Redes de Computadoras — Implementación de Herramienta de Diagnóstico Traceroute  
**Lenguaje**: C (C99/GNU99)  
**Estándares RFC**: RFC 791 (IPv4), RFC 792 (ICMP), RFC 768 (UDP), RFC 1071 (Internet Checksum)  
**Mecanismo de Red**: Sockets Crudos (`SOCK_RAW`, `IP_HDRINCL` para transmisión IPv4 y `SOCK_RAW`, `IPPROTO_ICMP` para recepción)  
**Directiva de Calidad**: 100% conforme a las directivas de arquitectura modular de `modularCoding` (funciones orquestadoras $\le 15$ líneas, sub-funciones atómicas de 5 a 15 líneas, compilación estricta sin advertencias) y sincronización `doc_sync`.

---

## 1. Visión General y Objetivos

`my_traceroute` es una implementación profesional, independiente y modular de la herramienta clásica de diagnóstico de rutas **Traceroute**, desarrollada en espacio de usuario sin utilizar librerías de alto nivel para construcción de paquetes (como `libnet` o `scapy`).

El programa descubre la topología de red intermedia hacia un destino arbitrario (dirección IPv4 o nombre FQDN) enviando paquetes de sondeo (*probes*) con valores de **Time-To-Live (TTL)** incrementales y analizando los mensajes de control **ICMP** generados por los enrutadores en el camino o por el host de destino.

### Características Principales:
1. **Sondeo UDP Clásico**: Datagramas ensamblados manualmente byte a byte con encabezado IPv4 (20 bytes), encabezado UDP (8 bytes) y payload (24 bytes), totalizando paquetes de 52 bytes.
2. **Correlación Obligatoria de Respuestas ICMP**: Desencapsulación e inspección profunda del payload devuelto en los mensajes ICMP para verificar que la cabecera IP original y los puertos UDP coincidan exactamente con la sonda emitida.
3. **Medición RTT de Alta Precisión**: Cálculo de tiempos de ida y vuelta en microsegundos/milisegundos utilizando relojes monotónicos (`clock_gettime(CLOCK_MONOTONIC)`).
4. **Resolución DNS Inversa Automática**: Búsqueda PTR mediante `getnameinfo(..., NI_NAMEREQD)` para reportar nombres de host calificados (`FQDN`) o fallback a IP en caso de ausencia de registro.
5. **Soporte Multipath**: Detección y despliegue visual claro cuando en un mismo salto responden routers distintos por balanceo de carga.
6. **Manejo de Parámetros CLI Completo**: Soporte de opciones para TTL inicial (`-f`), saltos máximos (`-m`), cantidad de probes (`-q`), timeout (`-w`) y pausa entre sondas (`-z`).

---

## 2. Arquitectura de Software y Patrón Modular (`modularCoding`)

El diseño del software implementa rigurosamente el **Patrón Orquestador**:
- Las funciones de alto nivel (`main`, `traceroute_run`, `trace_single_hop`, `execute_single_probe`, etc.) se limitan a orquestar el flujo llamando a sub-funciones atómicas, respetando el límite estricto de **$\le 15$ líneas de código**.
- Todas las tareas auxiliares (cálculo de checksums, armado de cabeceras, validación de datagramas, sondeo no bloqueante, formateo de texto) están aisladas en sub-funciones de 5 a 15 líneas con responsabilidad única.

### Diagrama Arquitectónico de Componentes

```
+---------------------------------------------------------------------------------+
|                               traceroute_main.c                                 |
|  - main() [Orquestador <= 15 lineas]                                            |
|  - parse_cli_arguments(), resolve_and_prepare_endpoints(), print_usage()       |
+---------------------------------------+-----------------------------------------+
                                        |
                                        v
+---------------------------------------+-----------------------------------------+
|                              traceroute_engine.c                                |
|  - traceroute_run()       [Orquestador <= 15 lineas]                            |
|  - run_hop_loop()         [Orquestador <= 15 lineas]                            |
|  - trace_single_hop()     [Orquestador <= 15 lineas]                            |
|  - execute_single_probe() [Orquestador <= 15 lineas]                            |
+-------+-------------------+-------------------+-------------------+-------------+
        |                   |                   |                   |
        v                   v                   v                   v
+---------------+   +---------------+   +---------------+   +---------------+
|  ip_header.c  |   | udp_header.c  |   | icmp_parser.c |   | dns_resolver.c|
|   (RFC 791)   |   |   (RFC 768)   |   |   (RFC 792)   |   |  (getaddrinfo/|
| build_ip_...  |   | build_udp_... |   | parse_and_... |   |  getnameinfo) |
+-------+-------+   +-------+-------+   +-------+-------+   +---------------+
        |                   |                   |
        +---------+---------+                   |
                  |                             |
                  v                             v
          +---------------+             +---------------+
          |  checksum.c   |             | raw_socket.c  |
          |  (RFC 1071)   |             | Sockets TX/RX |
          +-------+-------+             +-------+-------+
                  |                             |
                  +--------------+--------------+
                                 |
                                 v
               ====================================
                   RED / ENLACES IP / INTERNET
               ====================================
```

---

## 3. Matriz de Módulos y Responsabilidades

| Archivo | Responsabilidad | Funciones Orquestadoras ($\le 15$ líneas) | Sub-funciones Atómicas |
| :--- | :--- | :--- | :--- |
| **`traceroute_main.c`** | Punto de entrada CLI y parseo de argumentos | • `main()`<br>• `parse_cli_arguments()`<br>• `resolve_and_prepare_endpoints()` | • `init_default_config()`<br>• `parse_flag_value()`<br>• `parse_single_cli_argument()`<br>• `print_usage()` |
| **`traceroute_engine.h/c`** | Motor de la traza, bucle de saltos y probes | • `traceroute_run()`<br>• `run_hop_loop()`<br>• `trace_single_hop()`<br>• `execute_single_probe()` | • `init_traceroute_sockets()`<br>• `close_traceroute_sockets()`<br>• `print_traceroute_header()`<br>• `assemble_probe_packet()`<br>• `transmit_udp_probe()`<br>• `compute_elapsed_ms()`<br>• `record_matching_probe()`<br>• `await_matching_icmp_response()`<br>• `print_hop_number()`<br>• `print_responder_identity()`<br>• `print_probe_result()`<br>• `sleep_pause_interval()`<br>• `is_target_reached()` |
| **`ip_header.h/c`** | Ensamblaje de cabeceras IPv4 dinámicas | • `build_ip_header()` | • `set_ip_format_and_tos()`<br>• `set_ip_length_and_flags()`<br>• `set_ip_control_fields()`<br>• `set_ip_addresses()` |
| **`udp_header.h/c`** | Ensamblaje UDP y checksum con pseudo-header | • `build_udp_header()`<br>• `calculate_udp_checksum()` | • `fill_pseudo_header()`<br>• `allocate_udp_pseudo_packet()`<br>• `normalize_udp_checksum()` |
| **`icmp_parser.h/c`** | Desencapsulación y correlación de probes ICMP | • `parse_and_validate_icmp()` | • `validate_outer_ip()`<br>• `validate_inner_packet()`<br>• `match_inner_udp()`<br>• `match_inner_ip_dst()`<br>• `classify_icmp_type_code()`<br>• `extract_and_fill_result()` |
| **`dns_resolver.h/c`** | Resolución de nombres y búsqueda reversa PTR | • `resolve_target_hostname()`<br>• `reverse_dns_lookup()`<br>• `determine_local_ip_for_target()` | • `setup_hints()`<br>• `extract_ipv4_addr()`<br>• `setup_sockaddr_in()`<br>• `query_local_socket_ip()` |
| **`checksum.h/c`** | Algoritmo Internet Checksum (RFC 1071) | • `calculate_checksum()` | • `accumulate_words()`<br>• `add_odd_byte_if_any()`<br>• `fold_32bit_sum()` |
| **`raw_socket.h/c`** | Manejo de sockets crudos TX y RX con timeouts | • `create_raw_sender_socket()`<br>• `create_icmp_receiver_socket()`<br>• `send_raw_packet()`<br>• `receive_icmp_packet()` | • `enable_ip_hdrincl()`<br>• `set_socket_timeout()`<br>• `init_dest_sockaddr()`<br>• `close_socket_fd()` |

---

## 4. Especificación Binaria de Protocolos y Layouts de Memoria

Todos los encabezados se estructuran sin relleno de compilador mediante `#pragma pack(push, 1)`:

### A. Encabezado IPv4 (RFC 791) — 20 Bytes
```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |Type of Service|          Total Length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|      Fragment Offset    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Time to Live |    Protocol   |         Header Checksum       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Source IP Address                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination IP Address                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
- **Version/IHL**: `0x45` (IPv4, 20 bytes).
- **Time to Live (TTL)**: Variable, incrementado de `first_ttl` a `max_hops`.
- **Protocol**: `17` (`IPPROTO_UDP`).
- **Total Length**: 52 bytes (`sizeof(ip_header_t) + sizeof(udp_header_t) + 24`). En Linux en Network Byte Order, en macOS Darwin en Host Byte Order.

---

### B. Encabezado UDP (RFC 768) — 8 Bytes
```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Length             |           Checksum            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
- **Source Port**: Puerto efímero local generado a partir del PID (`40000 + (getpid() & 0x3FFF)`).
- **Destination Port**: Inicia en `33434` y se incrementa en `+1` por cada sonda transmitida.
- **Length**: `8 + 24 = 32` bytes (`sizeof(udp_header_t) + payload_len`).
- **Checksum**: Calculado sobre el Pseudo-Header IPv4 (12 bytes) + Encabezado UDP + Payload de datos. Si el cálculo resulta `0`, se transmite como `0xFFFF` según RFC 768.

---

### C. Encabezado ICMP (RFC 792) y Carga de Correlación
```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |     Code      |           Checksum            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Rest of Header                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Original IP Header (20 bytes) que causó el mensaje       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Primeros 64 bits (8 bytes) de la cabecera UDP original    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

El socket receptor ICMP recibe el paquete con la siguiente estructura anidada:
1. **IP Externa**: Dirección origen = Router o Host respondedor.
2. **ICMP Header**:
   - `Type = 11, Code = 0` (`ICMP_TIME_EXCEEDED`): Router intermedio detectado.
   - `Type = 3, Code = 3` (`ICMP_DEST_UNREACH` / Port Unreachable): Meta alcanzada.
3. **IP Interna Original**: Cabecera transmitida por nuestra herramienta.
4. **UDP Interno Original**: Contiene los puertos origen y destino que permiten comprobar que la respuesta corresponde exactamente al probe que enviamos.

---

## 5. Compilación y Requisitos

### Requisitos del Sistema
- Sistema Operativo: Linux (nativo o WSL2 Ubuntu) o macOS.
- Compilador: `gcc` o `clang` con soporte `gnu99`.
- Privilegios: `sudo` o `CAP_NET_RAW` para abrir sockets `SOCK_RAW`.

### Compilación Estricta
El proyecto incluye un `Makefile` con los flags más estrictos de calidad de código:
```bash
make clean && make
```
Flags utilizados:
```text
-O2 -Wall -Wextra -Werror -pedantic -std=gnu99 -g
```
*Garantiza cero advertencias (`0 warnings`) y código de retorno `0`.*

---

## 6. Guía de Uso y Opciones CLI

### Invocación Básica
```bash
sudo ./my_traceroute [opciones] <destino>
```

### Opciones Soportadas
| Opción | Argumento | Valor por Defecto | Descripción |
| :--- | :--- | :--- | :--- |
| `-f, --first-ttl` | `<num>` | `1` | TTL inicial con el que comienza la traza |
| `-m, --max-hops` | `<num>` | `64` | Número máximo de saltos antes de abortar |
| `-q, --probes` | `<num>` | `3` | Número de sondas enviadas por cada salto |
| `-w, --timeout` | `<seg>` | `3` | Tiempo máximo de espera por respuesta de cada sonda |
| `-z, --pause` | `<ms>` | `100` | Pausa en milisegundos entre sondas consecutivas |
| `-h, --help` | — | — | Muestra el menú de ayuda |

### Ejemplos de Ejecución

1. **Traza estándar hacia Google DNS**:
   ```bash
   sudo ./my_traceroute 8.8.8.8
   ```
2. **Traza rápida a Cloudflare limitando a 5 saltos y 2 probes**:
   ```bash
   sudo ./my_traceroute -m 5 -q 2 1.1.1.1
   ```
3. **Traza hacia un dominio FQDN con inicio en salto 2**:
   ```bash
   sudo ./my_traceroute -f 2 -m 15 galileo.edu
   ```

---

## 7. Validación Experimental y Comparación con Traceroute Nativo

Se ejecutó una prueba comparativa directa en el mismo entorno de red (WSL2 Ubuntu) comparando `my_traceroute` contra el comando nativo del sistema (`/usr/bin/traceroute`).

### A. Ejecución Lado a Lado contra `8.8.8.8`

```text
$ traceroute -m 3 -q 2 8.8.8.8
traceroute to 8.8.8.8 (8.8.8.8), 3 hops max, 60 byte packets
 1  DESKTOP-AT70I2G.mshome.net (172.17.32.1)  0.097 ms  0.084 ms
 2  192.168.0.1 (192.168.0.1)  4.048 ms  1.881 ms
 3  100.64.247.130 (100.64.247.130)  14.465 ms 100.64.247.131 (100.64.247.131)  10.582 ms

$ sudo ./my_traceroute -m 3 -q 2 8.8.8.8
traceroute to 8.8.8.8 (8.8.8.8), 3 hops max, 52 byte packets
 1  DESKTOP-AT70I2G.mshome.net (172.17.32.1)  0.161 ms  0.176 ms
 2  192.168.0.1 (192.168.0.1)  2.461 ms  2.333 ms
 3  100.64.247.131 (100.64.247.131)  10.352 ms  100.64.247.130 (100.64.247.130)  11.261 ms
```

### B. Análisis de Resultados y Comportamiento de Red:
1. **Exactitud de Ruta**: Ambos identifican exactamente los mismos saltos de red:
   - Salto 1: Gateway virtual de WSL2 (`172.17.32.1`, resuelto a `DESKTOP-AT70I2G.mshome.net`).
   - Salto 2: Gateway físico de la red local LAN (`192.168.0.1`).
   - Salto 3: Enrutadores del ISP (`100.64.247.130` y `100.64.247.131`).
2. **Multipath y Balanceo de Carga**: En el salto 3 se observa cómo diferentes probes toman caminos alternos hacia `100.64.247.130` y `100.64.247.131`. `my_traceroute` maneja y despliega ambas identidades con alineación impecable.
3. **Manejo de Paquetes**: `my_traceroute` utiliza paquetes estándar de 52 bytes (20 IP + 8 UDP + 24 payload), mientras que el `traceroute` moderno de Linux utiliza 60 bytes (20 IP + 8 UDP + 32 payload).
4. **Tiempos RTT**: Las mediciones coinciden dentro de las fluctuaciones naturales de latencia de red en rangos sub-milisegundo para la red interna y ~10 ms hacia el carrier.
