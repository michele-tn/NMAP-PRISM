# Schema XML Nmap / Nmap XML schema

## Italiano

`nmap.dtd` è una copia non modificata della DTD ufficiale Nmap, scaricata il
28 settembre 2026 da https://svn.nmap.org/nmap/docs/nmap.dtd.
Le attribuzioni e le condizioni di distribuzione sono conservate nel file.
La documentazione ufficiale indica la DTD come definizione del formato:
https://nmap.org/book/app-nmap-dtd.html.
Non è stato individuato un XSD ufficiale nelle pagine e nella directory sorgente
https://svn.nmap.org/nmap/docs/ consultate. Questa distribuzione non include
conversioni XSD non ufficiali.

Nmap Prism controlla la buona formazione XML e la radice `nmaprun` usando
DOMParser. Non esegue validazione DTD/XSD. La DTD è inclusa per riferimento e
per l'uso con validatori esterni. Il DOCTYPE (semplice, SYSTEM, PUBLIC, con
sezione interna vuota o DTD incorporata) viene rimosso prima del parsing:
nessuna risorsa esterna viene caricata. Le entità XML standard e i riferimenti
numerici funzionano; riferimenti a entità personalizzate non vengono risolti
e causano un errore XML. Nmap non necessita di queste entità per il suo output.

I riepiloghi mostrano host, indirizzi, nomi, sistema operativo, porte, servizi
e risultati NSE. Nei pannelli XML espandibili sono conservati tutti gli
attributi ed elementi aggiuntivi, inclusi classi OS, traceroute, tempi, motivi
di stato e tabelle NSE annidate. I metadati della scansione comprendono anche
hosthint, pre/post-script e runstats. Non ogni elemento XML ha un grafico
dedicato. Il limite d'importazione resta 20 MiB per file.

Gli export JSON e HTML conservano i dettagli degli host e delle porte nel
perimetro selezionato. I metadati globali della scansione sono esclusi dagli
export filtrati, perché possono descrivere altri obiettivi. Le porte escluse
non sono replicate nei metadati host. I file XML originali non sono modificati.

## English

`nmap.dtd` is an unmodified copy of the official Nmap DTD downloaded on
2026-09-28 from the source above. Its original copyright and permission
notices are retained. No official XSD was found in the consulted Nmap
documentation or source directory; no unofficial conversion is bundled.

The browser checks XML well-formedness and the `nmaprun` root, not DTD/XSD
validity. DOCTYPE declarations are removed before parsing; external resources
are never fetched. Standard XML entities and numeric references work. Custom
entity references are not expanded and produce an XML error.

Additional scan, host and port elements and attributes remain available in
expandable XML panels, including nested NSE tables, OS classes, traceroute,
timing, host hints, pre/post scripts and run statistics. Not every XML element
has a dedicated visualization. The import limit remains 20 MiB per file.
Filtered JSON/HTML reports retain metadata for included hosts and ports, but
omit global scan metadata that may describe targets outside that scope.
Original XML files remain unchanged.
