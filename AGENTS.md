# AGENTS.md — Loquere

Istruzioni per gli agenti (Claude Code, Codex, Cursor, …) che lavorano su questo repository.

## Il progetto

Loquere è un'app desktop nativa in Rust per chat, chiamate vocali e videochiamate **peer-to-peer, senza alcun server centrale**. Ogni installazione è un nodo; l'account è una coppia di chiavi locale; gli amici si aggiungono con link di invito firmati; in chiamata un host viene eletto dinamicamente; i nodi amici fanno da relay cifrato.

**Fonte di verità: [`design.md`](design.md).** Prima di toccare un'area, leggi la sezione corrispondente (il sommario dei titoli si ottiene con `grep -n '^#' design.md`). Le decisioni hanno un identificativo (`D-01`, `G-11`, `R-09`, …): citale nei commit e nelle PR quando le applichi.

**Stato:** solo design, nessun codice ancora. Il primo traguardo è **M0 — Fondamenta** (§23): crypto, account e `DeviceCert`, portachiavi, link di invito, filtro silenzioso + QUIC, archiviazione, simulatore. Criterio di uscita: due nodi sulla stessa LAN diventano amici e si scambiano messaggi da CLI.

## Regole non negoziabili

Vengono dal design; violarle richiede prima una modifica di `design.md` concordata con l'utente.

- **Nessun server** gestito dal progetto (G-4). Unica eccezione prevista: gateway push iOS, opt-in (D-19).
- **Nessuna pubblicazione** di dati dell'utente su reti o directory pubbliche, nemmeno cifrati (G-11): niente DHT, niente STUN/TURN pubblici.
- **Niente `tokio` né runtime asincroni** (D-02). Thread dedicati + `std::sync::mpsc` + ring buffer SPSC interni. QUIC con `quinn-proto` (sans-IO), mai `quinn`.
- **Sans-IO** (D-01): `loquere-wire`, `loquere-mesh`, `loquere-call`, `loquere-chat` sono macchine a stati pure. Ricevono eventi con un orologio iniettato e restituiscono azioni; non aprono socket e non leggono l'orologio di sistema.
- **Nessuna crittografia scritta in casa** (§17.4): solo primitive e protocolli da librerie consolidate (`rustls`, `openmls`, `ed25519-dalek`, `chacha20poly1305`, …). Nostra è solo la composizione.
- `#![forbid(unsafe_code)]` in `loquere-wire`, `loquere-mesh`, `loquere-call`, `loquere-chat`, `loquere-identity`.
- `zeroize` su tutte le chiavi in memoria.
- **Thread `audio-rt`**: niente allocazioni, niente lock, solo ring buffer lock-free.
- **MCP / canale di controllo** (D-12): le azioni che contattano altre persone (messaggi, chiamate, amicizie, inviti) richiedono sempre una conferma nell'interfaccia.
- Il canale di controllo JSON ascolta **solo su localhost**, con token in un file leggibile solo dall'utente.

## Dipendenze

Regola di §21: una crate entra solo se (a) implementarla è rischioso (crittografia) o molto costoso (codec, AEC, UI), (b) è Rust puro o un binding diretto alle API del sistema operativo, (c) ha licenza compatibile con `MIT OR Apache-2.0`.

- Prima di aggiungere una dipendenza, controlla la tabella di §21 e motiva la scelta; se non è in tabella, chiedi all'utente e aggiorna il design.
- **Scartate esplicitamente:** `tokio`/async, `quinn`, `libp2p`, `iroh`, `webrtc-rs`, SQLite, DHT Mainline, `snow`/Noise.
- Dopo ogni modifica alle dipendenze: `cargo tree` e `cargo deny check`.
- Cose da implementare internamente (niente crate): filtro silenzioso, verificatore chiavi per `rustls`, guida di `quinn-proto`, controllo bitrate, jitter buffer, ring buffer RT, PCP/NAT-PMP, beacon LAN, codifica binaria dei record, archiviazione a log, ordinamento commit MLS, frase di recupero, simulatore di rete.

## Struttura del workspace

```
crates/
  loquere-crypto     primitive, tipi chiave, zeroize, portachiavi OS
  loquere-identity   account, dispositivi, profilo, inviti, backup
  loquere-wire       filtro silenzioso, quinn-proto + rustls, canali
  loquere-net        socket, candidati, PCP/NAT-PMP/UPnP, punching, LAN
  loquere-mesh       peer table, percorsi, relay, gossip indirizzi
  loquere-call       stato chiamata, topologia, elezione host, chiavi media
  loquere-media      pipeline audio/video, jitter buffer, congestion control
  loquere-devices    I/O audio e cattura video per piattaforma
  loquere-chat       conversazioni, MLS, DAG messaggi, sync, casella postale, file
  loquere-store      log append-only cifrati, indici, configurazione
  loquere-engine     facciata unica: comandi in ingresso, eventi in uscita
  loquere-control    canale JSON e server MCP
  loquere-sim        simulatore di rete deterministico
apps/
  loquere            app desktop (egui)
  loquere-cli        CLI e nodo headless
```

Nomi di crate, binari e schema URL **sempre in minuscolo** (`loquere-<area>`, `loquere://`). "Loquere" con la maiuscola è solo il nome del prodotto e della cartella dati.

## Comandi

Da usare quando il workspace Cargo esiste:

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
cargo +nightly miri test -p <crate>     # ring buffer e codice con unsafe
cargo +nightly fuzz run <target>        # parser di pacchetti, inviti, record, frame
```

Prima di dichiarare finito un lavoro: `fmt`, `clippy` e `test` devono passare.

## Test

- Ogni macchina a stati sans-IO ha unit test e property test.
- Gli scenari di rete (NAT, perdita, partizioni, cambio host, MLS concorrente, revoca dispositivi) si testano in `loquere-sim` con seme fisso; l'elenco degli scenari obbligatori è in §22.
- Ogni parser che legge dati dalla rete ha un target di fuzzing, con priorità al percorso pre-autenticazione.
- Un bug di protocollo si riproduce con il log degli eventi prima di correggerlo.

## Lavorare con l'utente

- Documentazione di progetto e comunicazione in **italiano**; identificatori nel codice in inglese, come da convenzione Rust.
- Quando serve una decisione, chiedila in chat con **opzioni selezionabili** (la consigliata per prima), spiegando i termini tecnici in parole semplici. Non lasciare domande aperte sepolte nei documenti.
- Ogni decisione presa va riportata in `design.md` (registro di §25 e sezione interessata).
- Licenza: `MIT OR Apache-2.0`.
