#ifndef DNS_RESOLVER_H
#define DNS_RESOLVER_H

#include <stddef.h>
#include <netinet/in.h>

/*
 * Resuelve un nombre de dominio (FQDN) o IP textual a una estructura IPv4 binaria y texto.
 */
int resolve_target_hostname(const char *target, char *ip_str_out, size_t ip_str_sz,
                            struct in_addr *addr_out);

/*
 * Realiza búsqueda PTR inversa sobre una dirección IPv4. Retorna 1 si encontró hostname, 0 si no.
 */
int reverse_dns_lookup(const struct in_addr *addr, char *hostname_out, size_t max_len);

/*
 * Determina la dirección IPv4 de la interfaz local de salida hacia el destino mediante la tabla de rutas.
 */
int determine_local_ip_for_target(const struct in_addr *target_addr,
                                  char *local_ip_out, size_t max_len);

#endif /* DNS_RESOLVER_H */
