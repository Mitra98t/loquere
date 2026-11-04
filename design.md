# Loquere - Design Document

> **Stato:** design approvato, da validare con i prototipi · **Versione:** 0.2 · **Data:** 3 novembre 2026
> **Nome:** Loquere

---

## 1. Sommario

Loquere è un'applicazione desktop nativa, scritta in Rust, per chat testuale, chiamate vocali e videochiamate, uno-a-uno e di gruppo, **senza alcun server centrale**. Ogni istanza installata è un **nodo** di una rete peer-to-peer: ha un'identità crittografica generata localmente, può essere contattata dagli amici, può chiamarli e, se l'utente lo consente, può fare da **relay** per il traffico cifrato di altri nodi.

I punti caratterizzanti sono cinque:

1. **Account = coppia di chiavi locale.** Nessuna registrazione presso terzi. L'"account" è una chiave Ed25519 generata al primo avvio.
2. **Amicizia tramite link.** L'utente genera un link di invito firmato e lo manda a chi vuole (per email, messaggio, QR). Chi lo apre diventa amico dopo l'accettazione.
3. **Host di chiamata eletto dinamicamente.** In una chiamata di gruppo il sistema sceglie quale partecipante (o quale nodo amico esterno) fa da punto di inoltro dei flussi media, in base a banda, latenza e stabilità misurate, e lo cambia durante la chiamata se le condizioni cambiano.
4. **Mesh di relay tra amici.** Quando due nodi non riescono a parlarsi direttamente (NAT, firewall), il traffico passa attraverso un terzo nodo fidato (amico di tutti i partecipanti della chiamata), che vede solo pacchetti cifrati end-to-end.
5. **Un account, più dispositivi.** Lo stesso account vive su tutti i computer dell'utente; ogni dispositivo ha chiavi proprie certificate dall'account e revocabili. Un dispositivo lasciato acceso a casa fa da relay e da casella postale per gli altri (§6.4).

**Principio guida: tranquillità prima della comodità.** Nessun dato dell'utente viene pubblicato su reti o directory pubbliche, nemmeno cifrato: le informazioni circolano solo tra amici e tra i propri dispositivi. Quando sicurezza e comodità sono in conflitto, il valore predefinito è quello sicuro e la comodità è una scelta esplicita.

È un progetto **indipendente** che segue i principi dell'ecosistema **ArtCraft / Crafting Apps** (Rust puro, nativo, open source, locale, guidabile da CLI e agenti).

---

## 2. Obiettivi e non-obiettivi

### 2.1 Obiettivi (v1)

| # | Obiettivo |
|---|---|
| G-1 | Chat testuale 1:1 e di gruppo, con cronologia locale e consegna differita quando il destinatario torna online. |
| G-2 | Chiamate vocali 1:1 e di gruppo (fino a ~16 partecipanti audio). |
| G-3 | Videochiamate 1:1 e di gruppo (fino a ~8 partecipanti con video attivo). |
| G-4 | Nessun server gestito dal progetto: nessun componente obbligatorio esterno ai nodi degli utenti. Unica eccezione prevista, opzionale e solo per mobile: il gateway push (§20). |
| G-5 | Crittografia end-to-end di tutto il contenuto (testo, audio, video, file); i relay e l'host non-partecipante non vedono il contenuto. |
| G-6 | Elezione automatica e cambio dinamico dell'host di chiamata. |
| G-7 | Desktop multipiattaforma: macOS, Windows, Linux, FreeBSD (come le Crafting Apps). |
| G-8 | Dipendenze esterne minime e motivate una per una (§21). |
| G-9 | Ogni azione è scriptabile da CLI, canale di controllo JSON e server MCP (§19). |
| G-10 | Più dispositivi per lo stesso account, con sincronizzazione e revoca (§6.4). |
| G-11 | Nessuna pubblicazione: nessun dato dell'utente, nemmeno cifrato o anonimizzato, viene scritto su reti o directory pubbliche (§10.3). |

### 2.2 Obiettivi di qualità (target iniziali)

| Metrica | Target | Accettabile |
|---|---|---|
| Latenza bocca-orecchio (1:1, connessione diretta, stesso continente) | < 150 ms | < 250 ms |
| Interruzione audio durante un cambio host pianificato | < 60 ms | < 150 ms |
| Ripresa dopo la caduta improvvisa dell'host | < 1,5 s | < 3 s |
| Tempo dal "rispondi" al primo audio | < 1 s | < 2 s |
| CPU per una chiamata audio 1:1 su un portatile recente | < 5 % di un core | < 10 % |

### 2.3 Non-obiettivi (v1)

- **App mobile** (iOS/Android): prevista in una fase successiva, con i limiti spiegati in §20.
- **Versione web**: un browser non può aprire socket UDP grezzi, quindi non può essere un nodo completo (§20).
- **Rete aperta tra sconosciuti**: non è un social network né una rete di scoperta pubblica. Si comunica con amici e con i partecipanti a una chiamata a cui si è stati invitati.
- **Anonimato forte** stile Tor: i peer diretti vedono il tuo indirizzo IP (§17), salvo uso volontario di un relay.
- **Interoperabilità** con WebRTC, SIP, Matrix: non in v1.

---

## 3. Ispirazione: l'ecosistema ArtCraft

ArtCraft pubblica una famiglia di applicazioni desktop native ("Crafting Apps") con regole comuni. Loquere le adotta così:

| Principio ArtCraft | Applicazione in Loquere |
|---|---|
| Open source, licenze permissive | Codice su GitHub, licenza `MIT OR Apache-2.0` come le altre app della famiglia. |
| Nativo, non "wrappato": Rust puro, niente Electron o web view | UI in `egui`, binario nativo unico per piattaforma. |
| Familiare dal primo giorno | Layout da app di chat conosciuta: barra laterale contatti/gruppi, conversazione al centro, griglia video in chiamata. Scorciatoie standard (push-to-talk, muto, ecc.). |
| I tuoi file, la tua macchina | Identità, contatti e cronologia restano solo sul disco dell'utente, cifrati. Nessun cloud. Qui il principio è portato all'estremo: neanche la rete ha un centro. |
| Agent-ready (CLI, canale di controllo JSON, MCP) | `loquere-cli`, flag `--control <porta>`, server MCP con conferma esplicita per le azioni che contattano altre persone. |
| Workspace di crate con nome `<app>-<area>` | `loquere-wire`, `loquere-mesh`, `loquere-call`, ecc. (§5.2). |
| Distribuzione tramite ArtCraft Launcher, build per molte architetture, checksum SHA-256 | Progetto indipendente: rilasci propri (non tramite ArtCraft Launcher), con lo stesso tipo di pipeline: `.dmg` universale, `.msi` x64/ARM64, Flatpak/AppImage/deb/rpm, tarball FreeBSD, `SHA256SUMS.txt`. |
| Riuso tra app della famiglia | I/O audio con `cpal` invece del backend di SoundCraft, per non legare i cicli di rilascio. Resta il riuso del decoder H.264 in Rust puro dell'ecosistema (§14.2). |

---

## 4. Cosa significa davvero "senza server"

Questa sezione è volutamente esplicita, perché condiziona tutto il resto.

### 4.1 Il problema del primo contatto

Su Internet oggi la maggior parte dei dispositivi sta dietro un **NAT** (il router di casa, o il NAT dell'operatore nelle reti mobili, detto CGNAT). Un nodo dietro NAT **può iniziare** connessioni verso l'esterno ma **non può essere contattato** dall'esterno, a meno che:

- il router apra una porta su richiesta (UPnP / NAT-PMP / PCP);
- il nodo abbia un indirizzo IPv6 pubblico e il firewall consenta il traffico;
- i due nodi eseguano un **hole punching** coordinato, cioè si mandino pacchetti nello stesso momento, cosa che richiede un terzo nodo che li coordini;
- un terzo nodo raggiungibile faccia da **relay**.

Le soluzioni commerciali (WebRTC, Zoom, Discord, Tailscale) risolvono questo con server di segnalazione, STUN e TURN/relay gestiti dall'azienda.

### 4.2 La soluzione di Loquere

Loquere sostituisce ogni ruolo del server con **un nodo amico**:

| Ruolo tradizionale | In Loquere |
|---|---|
| Server di account | Chiave locale (§6) |
| Server di segnalazione / rubrica | Gossip degli indirizzi tra amici (§10) |
| STUN (scoprire il proprio IP pubblico) | Gli amici connessi ti dicono da quale indirizzo ti vedono (§9.3) |
| Coordinatore dell'hole punching | Un amico comune connesso a entrambi (§9.4) |
| TURN (relay del traffico) | Un amico raggiungibile che accetta di fare relay (§11) |
| SFU (server che inoltra i flussi di gruppo) | L'host eletto della chiamata (§13) |

### 4.3 Limite fisico da accettare (R-01)

Se **due** nodi sono entrambi dietro NAT restrittivi (tipicamente NAT "simmetrico" o CGNAT), **non** hanno IPv6 utilizzabile, **non** possono aprire porte sul router **e** non hanno **nessun nodo raggiungibile in comune**, allora non esiste alcun modo di metterli in contatto senza un terzo partecipante. Non è un limite dell'implementazione: è come funziona la rete.

Mitigazioni, in ordine:

1. **IPv6 prima di tutto** (§9.1): molte reti domestiche e mobili lo hanno già.
2. **Apertura porte automatica** sul router (§9.2).
3. **Un proprio dispositivo sempre acceso** (§6.4): il computer di casa lasciato acceso fa da punto d'incontro, relay e casella postale per gli altri dispositivi dell'utente e, se lo si consente, per i suoi amici.
4. **Nodo "àncora"** (§19.4): basta che **un** amico della rete abbia un nodo sempre acceso e raggiungibile (anche un Raspberry Pi a casa con una porta aperta, o un piccolo VPS) perché tutti i suoi amici possano incontrarsi tramite lui. È lo stesso binario in modalità senza interfaccia: **non è un server del progetto, è un nodo come gli altri**.

La 0.1 proponeva anche, come opzione, la pubblicazione cifrata del proprio indirizzo sulla DHT pubblica di BitTorrent. È **scartata** (G-11, §10.3).

---

## 5. Architettura generale

### 5.1 Livelli

```
┌───────────────────────────────────────────────────────────────────┐
│ UI (egui)              CLI              Control JSON / MCP        │  app/
├───────────────────────────────────────────────────────────────────┤
│                      loquere-engine                               │  comandi, eventi,
│        (facciata unica: comandi in ingresso, eventi in uscita)    │  stato applicativo
├──────────────┬──────────────┬───────────────┬─────────────────────┤
│ loquere-     │ loquere-     │ loquere-      │ loquere-store       │
│ chat         │ call         │ media         │ (persistenza)       │
│ (messaggi,   │ (segnalaz.,  │ (audio, video,│                     │
│  sync, file) │  elezione    │  jitter, CC)  │                     │
│              │  host)       │               │                     │
├──────────────┴──────────────┴───────────────┴─────────────────────┤
│ loquere-mesh   (tabella peer, percorsi, relay, gossip indirizzi)  │
├───────────────────────────────────────────────────────────────────┤
│ loquere-wire   (filtro silenzioso, QUIC/TLS, canali, datagrammi)  │
├───────────────────────────────────────────────────────────────────┤
│ loquere-net    (socket UDP, NAT, PCP/UPnP, hole punching, LAN)    │
├───────────────────────────────────────────────────────────────────┤
│ loquere-crypto / loquere-identity                                 │
└───────────────────────────────────────────────────────────────────┘
        loquere-devices (microfono, altoparlanti, webcam) ──► media
```

### 5.2 Workspace

```
loquere/
├── crates/
│   ├── loquere-crypto      # wrapper sulle primitive, tipi chiave, zeroize, portachiavi OS
│   ├── loquere-identity    # account, dispositivi, profilo, inviti, backup
│   ├── loquere-wire        # filtro silenzioso, quinn-proto + rustls, verificatore chiavi, canali
│   ├── loquere-net         # socket, candidati, PCP/NAT-PMP/UPnP, punching, LAN
│   ├── loquere-mesh        # peer table, scelta percorsi, circuiti relay, gossip
│   ├── loquere-call        # stato chiamata, topologia, elezione host, chiavi media
│   ├── loquere-media       # pipeline audio/video, jitter buffer, congestion control
│   ├── loquere-devices     # I/O audio e cattura video per piattaforma
│   ├── loquere-chat        # conversazioni, MLS, DAG messaggi, sync, casella postale, file
│   ├── loquere-store       # log append-only cifrati, indici, configurazione
│   ├── loquere-engine      # comandi, eventi, orchestrazione
│   ├── loquere-control     # canale JSON e server MCP
│   └── loquere-sim         # simulatore di rete deterministico per i test (§22)
└── apps/
    ├── Loquere             # app desktop (egui)
    └── loquere-cli         # CLI e modalità nodo headless
```

### 5.3 Principio "sans-IO" (D-01)

**D-01.** Tutta la logica di protocollo (`wire`, `mesh`, `call`, `chat`) è scritta come **macchine a stati pure**: ricevono eventi (`pacchetto ricevuto`, `timer scaduto`, `comando utente`) con un orologio iniettato, e restituiscono azioni (`invia pacchetto`, `imposta timer`, `emetti evento`). Nessuna di queste crate apre socket o legge l'orologio di sistema.

Motivazioni:
- test deterministici di scenari di rete complessi (NAT, perdita, partizioni, cambio host) nel simulatore `loquere-sim`, senza rete reale;
- nessun runtime asincrono richiesto nel cuore del protocollo;
- riproducibilità dei bug: un log di eventi riproduce esattamente la sessione.

### 5.4 Modello dei thread (D-02)

**D-02.** Niente `tokio` né altri runtime asincroni. Il traffico è di pochi socket e pochi peer: bastano thread dedicati e code. QUIC non cambia questa scelta: si usa `quinn-proto` (sans-IO) guidato dal thread `net`, non il wrapper asincrono `quinn`.

| Thread | Compito | Vincoli |
|---|---|---|
| `net` | `recv` bloccante con timeout sui socket UDP (uno per IPv4, uno per IPv6), filtro silenzioso, endpoint `quinn-proto`, ruota dei timer, invio | unico proprietario dei socket |
| `engine` | esegue le macchine a stati sans-IO | nessun I/O bloccante |
| `audio-rt` | callback del dispositivo audio (cattura e riproduzione) | tempo reale: nessuna allocazione, nessun lock; solo ring buffer lock-free SPSC |
| `audio-proc` | AEC, soppressione rumore, AGC, codifica/decodifica Opus, mix | blocchi da 10 ms |
| `video-enc` / `video-dec` | codifica e decodifica video | uno per flusso o pool limitato |
| `ui` | egui | riceve snapshot di stato, invia comandi |

Comunicazione tramite `std::sync::mpsc` e ring buffer lock-free SPSC in **implementazione interna** (~200 righe), verificata con Miri e test di stress multi-thread.

---

## 6. Identità e account

### 6.1 Creazione

Al primo avvio l'utente sceglie se **creare un account** o **collegare questo dispositivo a un account esistente** (§6.4). Nel primo caso:

1. Si genera la **chiave dell'account** Ed25519 (`IK`). La chiave pubblica è l'**AccountId**, mostrato come stringa base32 a 52 caratteri e come impronta breve leggibile (es. `tc-7HQK-M2PA`). È ciò che gli amici conoscono di te.
2. Si genera la **chiave del dispositivo** Ed25519 (`DK`), legata all'account da un `DeviceCert` firmato da `IK` (§6.4). È anche la chiave con cui il dispositivo si presenta nell'handshake TLS (§8.3). Separarla dall'account permette di ruotarla o revocarla senza cambiare account. In questo documento **nodo** = un dispositivo.
3. Si genera il **segreto di scoperta** `D` (32 byte casuali), unico per l'account e condiviso con gli amici e con i propri dispositivi (§10.1).
4. L'utente sceglie nome visualizzato e, opzionalmente, avatar. Il **profilo** è un record firmato con numero di sequenza.
5. **Protezione delle chiavi a riposo.** I file con le chiavi private sono cifrati con una **chiave master** casuale `MK` (ChaCha20-Poly1305). `MK` è custodita nel **portachiavi del sistema** dove disponibile (predefinito, per comodità), oppure derivata da una **passphrase** (Argon2id). Le operazioni che usano `IK` (collegare o revocare dispositivi, esportare il backup) richiedono sempre una conferma: passphrase o autenticazione del sistema (Touch ID, Windows Hello).

| OS | Portachiavi | Note di sicurezza |
|---|---|---|
| macOS | Keychain (Security.framework via `objc2`) | accesso legato alla firma del codice dell'app: un altro programma non legge `MK` senza un avviso del sistema |
| Windows | Credential Manager + DPAPI (crate `windows`) | protegge dal furto del disco, non da malware che gira come l'utente |
| Linux / FreeBSD | Secret Service via D-Bus (GNOME Keyring, KWallet) | qualunque processo dell'utente può leggere i segreti: l'interfaccia lo spiega e suggerisce la passphrase; se il servizio manca, solo passphrase. Client D-Bus: `zbus` |

### 6.2 Backup e ripristino

Senza server, se si perde la chiave si perde l'account. Quindi:

- **Frase di recupero** di 24 parole che codifica il seme da cui derivano `IK` e `D` (derivazione HKDF con etichette distinte). Le chiavi di dispositivo non ne derivano: ripristinare l'account su un computer significa crearvi un **nuovo dispositivo amministratore**, che può poi revocare quelli persi.
- **Esportazione** di un file cifrato con passphrase che contiene anche contatti e, a scelta, la cronologia.
- **Un secondo dispositivo collegato è già un backup** dell'account e della cronologia (§6.4).
- L'interfaccia **insiste** sul backup alla creazione dell'account (schermata dedicata, non saltabile senza conferma esplicita).

### 6.3 Profilo

```
Profile {
  account_id:   Ed25519Pub,       // IK
  seq:          u64,              // il più alto vince
  display_name: String (≤ 64 B),
  avatar:       Option<Blake3Hash>, // il file viene scaricato dai dispositivi dell'account su richiesta
  devices_seq:  u64,              // versione corrente della DeviceList (§6.4)
  sig:          Signature         // IK
}
```

### 6.4 Più dispositivi per lo stesso account (D-13)

**D-13.** L'account è la radice di fiducia; ogni dispositivo ha chiavi proprie, certificate dall'account. Gli amici vedono **un** contatto, qualunque sia il numero di dispositivi.

**D-20. Encoding di `DeviceCert`.** La firma copre una codifica binaria canonica, senza dipendenze di serializzazione: il dominio ASCII `loquere:device-cert:v1\0`, seguito nell'ordine da `account_id` (32 byte), `device_id` (32 byte), `role` (1 byte: `0` Admin, `1` Member), `created_at` (u64 little-endian, secondi Unix), lunghezza del nome (u16 little-endian) e nome UTF-8. La lunghezza è in byte e deve essere compresa tra 1 e 65535. Il prefisso di dominio separa queste firme da ogni altro uso della stessa chiave.

**D-21. Parametri passphrase.** L'envelope cifrato con passphrase usa Argon2id v1.3 con memoria 64 MiB, 3 passaggi, parallelismo 1 e output di 32 byte; salt casuale di 16 byte. I parametri sono fissi per la versione 1 dell'envelope, così l'apertura non dipende da valori forniti dal file. Il payload è poi cifrato con ChaCha20-Poly1305 e nonce casuale di 12 byte. Modifiche ai parametri richiedono una nuova versione dell'envelope.

**D-22. File identità locale.** Il plaintext cifrato di `identity.tck` ha magic/versione `LOQID\x01\0\0`, poi chiave privata account (32 B), chiave privata dispositivo (32 B), segreto `D` (32 B), lunghezza del `DeviceCert` (u32 little-endian) e certificato. L'intero payload è cifrato con ChaCha20-Poly1305 usando `loquere:identity:v1` come dati associati. In apertura si verifica il certificato e che le due chiavi private corrispondano a identità e dispositivo certificati.

**D-23. Protezione passphrase di `identity.tck`.** Si genera una MK casuale di 32 byte; il payload identità è cifrato con MK. L'envelope esterno contiene `LOQPRT\x01\0`, lunghezza u32 little-endian dell'envelope MK, lunghezza u32 dell'identità cifrata, envelope MK e identità cifrata. La MK è avvolta con Argon2id/ChaCha20-Poly1305 usando `loquere:master-key:v1` come dati associati.

```
DeviceCert {
  account_id,
  device_id:     Ed25519Pub,     // DK, anche chiave TLS del dispositivo (§8.3)
  name:          String,         // "MacBook", "Fisso di casa"
  role:          Admin | Member, // solo Admin custodisce IK
  created_at,
  sig                            // IK
}

DeviceList {
  account_id, seq,
  devices: [DeviceCert ...],
  revoked: [device_id ...],
  sig                            // IK
}
```

**Ruoli.** Un dispositivo **Admin** custodisce `IK` e può collegare e revocare dispositivi, creare inviti e firmare il profilo. Un dispositivo **Member** ha solo le proprie chiavi: chatta, chiama, fa da relay, ma se viene compromesso non può prendersi l'account. Predefinito: il primo dispositivo è Admin; i successivi sono Member salvo scelta esplicita; un nodo headless sempre acceso (§19.4) è **sempre** Member, perché è il più esposto.

**Collegare un nuovo dispositivo:**

1. Il nuovo dispositivo genera `DK` e mostra un **QR** (o un codice `TCL-…` da copiare) con `device_id`, un token monouso e i propri candidati. Il codice scade dopo 10 minuti.
2. Un dispositivo Admin lo scansiona e apre una connessione QUIC verso il nuovo dispositivo presentando il token: sulla LAN se possibile, altrimenti via Internet o via un altro proprio dispositivo come relay.
3. Entrambi mostrano un **codice di verifica** di 6 cifre derivato dall'hash dell'handshake; l'utente conferma che coincide. Questo esclude la sostituzione del QR da parte di terzi.
4. L'Admin firma il `DeviceCert`, pubblica una nuova `DeviceList` e trasferisce sulla sessione: `D`, contatti, blocchi, impostazioni condivise, l'ingresso del nuovo dispositivo in tutti i gruppi MLS (§15.4) e, se l'utente lo sceglie, la cronologia. `IK` viene trasferita solo se il nuovo dispositivo è Admin.

**Sincronizzazione tra i propri dispositivi.** I dispositivi dell'account formano un gruppo MLS privato, il **canale dell'account**, che trasporta contatti, blocchi, impostazioni condivise e stato di lettura. Inoltre ogni dispositivo è membro di ogni conversazione dell'account (ciascuno come foglia MLS distinta), quindi la cronologia si allinea con lo stesso meccanismo del DAG (§15.2).

**Chiamate.** Un `CallInvite` arriva a tutti i dispositivi online dell'account; il primo che risponde invia `CallAnswer` e gli altri ricevono `AnsweredElsewhere` e smettono di squillare.

**Il computer di casa come relay.** I propri dispositivi sono **sempre relay ammessi l'uno per l'altro** (§11.2). Un fisso lasciato acceso con una porta mappata è il punto d'incontro naturale del portatile quando si è fuori: coordina l'hole punching, inoltra il traffico se serve, custodisce la casella postale (§15.3) e permette di nascondere l'IP del portatile agli interlocutori (§17.2). Se l'utente lo consente, offre gli stessi servizi agli amici, come un'àncora.

**Revoca.** Da un dispositivo Admin, o dalla frase di recupero: nuova `DeviceList` senza il dispositivo, rotazione di `D`, rimozione della sua foglia da tutti i gruppi MLS (non legge più i messaggi futuri), chiusura delle sessioni con gli amici. Gli amici scartano subito ogni handshake con un `device_id` revocato.

**Trasparenza verso gli amici.** Quando un account aggiunge un dispositivo, gli amici ricevono la nuova `DeviceList` firmata, quindi non serve riverificare il numero di sicurezza. Un avviso discreto ("Bob ha collegato un nuovo dispositivo") è attivo di default: se qualcuno collegasse un dispositivo all'account di Bob a sua insaputa, lui o i suoi amici se ne accorgerebbero. Disattivabile.

---

## 7. Link di invito e amicizia

### 7.1 Formato del link

```
loquere://invite/<payload-base32>
```

oppure, per i canali che non rendono cliccabili gli schemi personalizzati, il solo testo `TC1-<payload-base32>` da incollare nell'app, e un **codice QR** con lo stesso contenuto.

Payload binario (versione 1):

| Campo | Dimensione | Note |
|---|---|---|
| `version` | 1 B | `1` |
| `account_id` | 32 B | `IK` pubblica |
| `device_id` | 32 B | `DK` del dispositivo che ha creato l'invito; serve per il filtro e per l'handshake TLS |
| `cert_len` + `certificate` | 2 B + cert | lunghezza u16 little-endian e `DeviceCert` completo firmato da `IK` |
| `invite_token` | 16 B | casuale; autorizza il primo contatto |
| `expires_at` | 4 B | secondi Unix; 0 = mai |
| `flags` | 1 B | bit 0 monouso, bit 1 auto-accetta; gli altri riservati a zero |
| `display_len` + `display_name` | 1 B + ≤32 B | lunghezza in byte e testo UTF-8, solo suggerimento |
| `candidate_count` + `candidates` | 1 B + 0–4 × 19 B | famiglia 4/6, indirizzo di 16 B, porta u16 big-endian; IPv4 nei primi 4 byte e poi 12 zero |
| `signature` | 64 B | `DK` firma i campi precedenti con dominio `loquere:invite:v1\0` |

Lunghezza tipica: ~320 byte → ~510 caratteri base32. Sufficiente per un QR di densità media.

**D-24. Invito verificabile.** Il payload include il `DeviceCert` completo, non solo la sua firma: così chi riceve può verificare la catena `IK` → `DK` prima di fidarsi dell'invito. Il certificato è preceduto da `cert_len` u16 little-endian. Tutte le lunghezze sono in byte; i candidati IPv4 usano 12 byte finali a zero. La firma DK copre i byte canonici dal campo `version` all'ultimo candidato, preceduti dal dominio ASCII `loquere:invite:v1\0`. Codifica Base32 RFC 4648 maiuscola senza padding.

**D-03.** Il token di invito è obbligatorio: un nodo **non risponde** a un handshake da uno sconosciuto che non presenta un token valido (§8.3). Questo rende il nodo invisibile agli scanner di porte.

**Privacy (R-02).** Il link contiene il tuo indirizzo IP corrente. Condividerlo pubblicamente (es. su un social) espone l'IP. L'interfaccia lo dice chiaramente e offre:
- link **senza indirizzi** (funziona solo se il destinatario ha un amico in comune con te);
- link che punta al **proprio dispositivo di casa** invece che a quello in uso: chi lo riceve vede l'IP di casa, non quello della rete su cui si trova il portatile;
- link **monouso** e con scadenza breve come impostazione predefinita (es. 7 giorni);
- **revoca** di qualunque invito attivo.

### 7.2 Flusso di amicizia

```
 Alice                                                         Bob
   │  1. genera invito (token T) e lo manda a Bob fuori banda  │
   │ ─────────────── (email, chat, QR) ─────────────────────▶  │
   │                                                           │
   │  2. Bob incolla il link; il suo nodo prova i candidati    │
   │ ◀────────── QUIC/TLS + FriendRequest{T, profilo}          │
   │                                                           │
   │  3. Alice verifica T. Se valido: conferma.                │
   │     Se T non è valido: chiude senza motivazione.          │
   │ ───────────────────────────────────────── FriendAck ────▶ │
   │                                                           │
   │  4. Notifica "Bob vuole aggiungerti" (o auto-accetta se   │
   │     l'invito era monouso e marcato auto-accetta)          │
   │                                                           │
   │  5. FriendAccept: scambio di profili, DeviceList,         │
   │     segreti di scoperta D_A e D_B, record indirizzi,      │
   │     capacità relay                                        │
   │ ◀────────────────────────────────────────────────────────▶│
   │                                                           │
   │  Ora sono amici in modo simmetrico.                       │
```

Se nessun candidato del link risponde (Alice offline o non raggiungibile), il nodo di Bob mette la richiesta **in coda** e riprova periodicamente, sfruttando anche eventuali amici comuni per trovare Alice (§10.2).

### 7.3 Rimozione di un amico e blocco

- **Rimuovi:** si cancella il contatto e si **ruota il proprio segreto di scoperta** `D`, ridistribuendolo agli amici rimasti e ai propri dispositivi. L'ex amico non può più trovare il tuo indirizzo tramite gossip.
- **Blocca:** come sopra, più una lista di `account_id` (sincronizzata tra i propri dispositivi) i cui handshake vengono scartati.

---

## 8. Trasporto e protocollo wire

### 8.1 Scelte di fondo

**D-04.** Trasporto **QUIC** (RFC 9000) su **UDP**, con la crate **`quinn-proto`** e TLS 1.3 tramite **`rustls`**. Davanti a QUIC c'è un **filtro silenzioso** sottile (§8.3, D-14).

Motivazioni:
- i media richiedono pacchetti **non affidabili** (un pacchetto audio in ritardo è inutile); il testo e il controllo richiedono pacchetti **affidabili e ordinati**. QUIC offre entrambi sulla stessa connessione: stream affidabili e `DATAGRAM` non affidabili (RFC 9221);
- UDP è l'unico trasporto con cui l'hole punching funziona bene, e QUIC gira su UDP;
- trasporto, ritrasmissioni, controllo di flusso, migrazione di percorso e handshake vengono da codice **maturo e molto usato** invece che da codice nostro: meno superficie da scrivere, testare e revisionare;
- `quinn-proto` è il cuore di `quinn` scritto come **macchina a stati senza I/O**: si integra con il principio sans-IO (D-01) e con il simulatore, e **non richiede un runtime asincrono** (D-02). Il wrapper `quinn`, che richiede `tokio`, non si usa.

Costo accettato: più dipendenze (`quinn-proto`, `rustls` e un provider crittografico) e un formato più complesso del protocollo proprio della 0.1.

### 8.2 Connessioni, stream e datagrammi

Tra due dispositivi c'è **una connessione QUIC** (ALPN `loquere/1`), che multiplexa:

| Canale | Tipo QUIC | Uso |
|---|---|---|
| controllo | stream bidirezionale 0 | segnalazione, metriche, piani di topologia |
| chat | stream bidirezionale dedicato | messaggi MLS, sincronizzazione del DAG |
| file | uno stream unidirezionale per trasferimento | blocchi da 64 KiB (§15.5) |
| media | `DATAGRAM` con un `stream_id` interno | audio e video cifrati a livello di frame (§12.4) |

- Keepalive: `PING` di QUIC; RTT e perdita vengono dalle statistiche della connessione.
- Dimensione massima del datagramma: si parte da **1200 byte** (il minimo garantito da QUIC) con scoperta della MTU attiva.
- **0-RTT disattivato**: i dati 0-RTT sono rigiocabili, e il guadagno (un RTT alla riconnessione) non vale il rischio.

### 8.3 Handshake, identità e filtro silenzioso

**D-05.** **TLS 1.3 con mutua autenticazione a chiave pubblica grezza** (RFC 7250, niente certificati X.509 né autorità di certificazione): ogni dispositivo si presenta con la propria chiave `DK` Ed25519. Il verificatore personalizzato di `rustls` accetta la chiave dell'altro solo se è un dispositivo non revocato di un amico (`DeviceList`), un proprio dispositivo, il dispositivo di un invito, o un partecipante del biglietto di chiamata.

- chi inizia conosce già la chiave di chi risponde (dal link di invito, dalla `DeviceList` di un amico o dal biglietto di chiamata) e rifiuta qualunque altra chiave: niente "man in the middle";
- 1 RTT per stabilire la connessione, forward secrecy grazie alle chiavi effimere di TLS 1.3;
- suite preferita `TLS_CHACHA20_POLY1305_SHA256`, con AES-GCM ammesso dove c'è accelerazione hardware; provider crittografico `ring`;
- il primo messaggio sullo stream di controllo dice perché ci si collega: `FriendRequest{token}`, `Hello{}` tra amici, `DeviceLink{token}` tra dispositivi dello stesso account (§6.4), oppure `CallJoin{call_ticket}` tra partecipanti non amici di una chiamata (§12.2). Se non è autorizzato, la connessione viene chiusa senza motivazione.

**D-14. Filtro silenzioso (loquere-gate).** QUIC, da solo, risponde a chiunque mandi un pacchetto iniziale ben formato: una scansione capirebbe che lì c'è un servizio, e il parser TLS sarebbe esposto a tutti. Per evitarlo, il socket passa da un filtro, sotto `quinn-proto`, che scarta senza risposta tutto ciò che non supera questi controlli:

- **Pacchetti iniziali** (header lungo QUIC): devono essere preceduti da un prefisso di 40 byte, `timestamp (8 B) ‖ gate_key_id (16 B) ‖ MAC (16 B)`. `gate_key_id` è un identificatore opaco derivato da una credenziale casuale condivisa per relazione; il MAC keyed BLAKE2s copre `timestamp ‖ gate_key_id ‖ pacchetto QUIC` e la chiave deriva con HKDF-SHA256 dalla credenziale e dal `DK` del destinatario. Nel primo contatto la credenziale è il token casuale dell'invito (bearer secret), poi viene conservata per la relazione. Il solo `DeviceId` pubblico non è una chiave e non autorizza pacchetti. Il timestamp deve stare in una finestra di ±120 s e il pacchetto non deve essere già stato visto da quella sorgente.
- **Pacchetti successivi** (header corto): i Connection ID li generiamo noi come `casuale ‖ MAC(chiave locale, casuale)`, quindi il filtro riconosce quelli validi senza tenere stato. Nessun byte in più sui pacchetti dei media.
- Tutto il resto (versioni sconosciute, Connection ID inventati, pacchetti troncati) viene scartato. `quinn-proto` non invia mai *version negotiation* né *stateless reset* verso l'esterno.

Il formato sul cavo non è più QUIC "puro", ma è indifferente: un nodo Loquere parla solo con altri nodi Loquere. Il filtro è il **solo codice raggiungibile da un estraneo** (obiettivo ~200 righe, §9.6).

Protezione da DoS, sopra il filtro: **Retry** di QUIC (convalida dell'indirizzo senza allocare stato) quando il nodo è sotto carico; limite di amplificazione di QUIC (mai più di 3 volte i byte ricevuti prima della convalida); limiti per sorgente.

### 8.4 Affidabilità e controllo di congestione

Ritrasmissioni, ACK, controllo di flusso e congestione degli stream sono quelli di `quinn-proto` (algoritmo BBR). I datagrammi media sono anch'essi soggetti al controllo di congestione della connessione; il controllo del bitrate dei media (§14.4) lavora sopra, adattando gli encoder prima che QUIC debba scartare datagrammi.

### 8.5 Migrazione di percorso

Nativa in QUIC: se l'indirizzo di un peer cambia (Wi-Fi → rete mobile), la connessione verifica il nuovo percorso (`PATH_CHALLENGE`/`PATH_RESPONSE`) e continua senza nuovo handshake. I nuovi Connection ID passano dal filtro come sopra.

---

## 9. Raggiungibilità e attraversamento del NAT

### 9.1 Candidati

Ogni nodo mantiene la lista dei propri **candidati**, cioè gli indirizzi a cui potrebbe essere raggiunto, in ordine di preferenza:

1. **IPv6 globale** dell'interfaccia (spesso raggiungibile direttamente o con punching banale).
2. **Porta mappata** sul router tramite PCP / NAT-PMP / UPnP-IGD (§9.2).
3. **Indirizzo riflesso** (IP:porta pubblico come visto da un peer, §9.3).
4. **Indirizzi LAN** (utili per amici sulla stessa rete).

### 9.2 Apertura automatica delle porte

All'avvio e ogni 30 minuti il nodo prova, in ordine, **PCP** (RFC 6887), **NAT-PMP** (RFC 6886), **UPnP-IGD**. PCP e NAT-PMP sono protocolli binari minuscoli: implementazione interna. UPnP (SSDP + HTTP + XML SOAP) usa la crate **`igd-next`** con API sincrona.

**D-15.** Politica di apertura:

- **una sola porta UDP** per famiglia di indirizzi, per tutto (chat, chiamate, video, relay). Nessuna porta TCP, nessun intervallo di porte aperto per i media, nessuna porta in più durante le chiamate. Il canale di controllo ascolta solo su localhost (§19.2);
- numero di porta **casuale**, scelto all'installazione (non una porta fissa che identifichi Loquere a una scansione di massa) e cambiato a ogni cambio di rete;
- mappature con **lease breve** (1 h, rinnovato); rimozione esplicita alla chiusura dell'app; se l'app si chiude male, la mappatura scade da sola;
- risposte UPnP accettate **solo dal gateway predefinito**, ignorate da altri dispositivi della LAN;
- Loquere **non chiede mai** di attivare UPnP sul router: se è spento resta spento, e si usano gli altri meccanismi;
- impostazione **Raggiungibilità**: *Automatica* (predefinita: mappatura se il router la offre) oppure *Solo in uscita* (nessuna mappatura: il nodo è raggiungibile solo tramite hole punching coordinato o relay, ad esempio il proprio computer di casa). I compromessi delle due modalità sono in §9.6.

### 9.3 Scoperta dell'indirizzo pubblico senza STUN

Ogni `PONG` contiene il campo `observed_addr`: l'indirizzo sorgente da cui il peer ha visto arrivare il `PING`. Confrontando quanto riportato da **almeno due peer diversi**, il nodo capisce:

- il proprio IP:porta pubblico;
- il **tipo di NAT**: se peer diversi vedono porte diverse per lo stesso socket locale, il NAT è *simmetrico* (dipendente dalla destinazione) e l'hole punching sarà difficile.

### 9.4 Hole punching coordinato da un amico comune

```
        Alice (NAT)              Carla (raggiungibile,           Bob (NAT)
                                 amica di entrambi)
           │  PunchRequest{Bob, cand_A} │                          │
           │ ─────────────────────────▶ │  PunchRequest{Alice,     │
           │                            │  cand_A, t0} ──────────▶ │
           │  PunchSync{cand_B, t0}     │                          │
           │ ◀───────────────────────── │                          │
           │                                                       │
           │  a t0: probe UDP verso cand_B  ◀──────▶  a t0: probe verso cand_A
           │                (il primo che passa apre il varco)     │
           │ ◀═════════════ handshake QUIC diretto ══════════════▶ │
```

- I probe sono pacchetti iniziali QUIC reali, con il prefisso del filtro: se arrivano, la connessione parte subito. Lo stesso endpoint `quinn-proto` fa da client e da server sullo stesso socket; se entrambi i lati aprono una connessione, resta quella avviata dal dispositivo con `device_id` minore.
- Con NAT simmetrico da un lato si tenta la **previsione delle porte** (raffiche verso un intervallo di porte vicine) con un limite di tentativi; se fallisce, si passa al relay (§11).
- Il coordinatore può essere qualunque nodo connesso a entrambi: un amico comune, o l'host di una chiamata in corso.

### 9.5 Mantenimento

Keepalive (`PING` di QUIC) ogni **25 s** sui percorsi attivi per tenere aperti i varchi nel NAT. L'intervallo si adatta: se un varco si chiude prima, il nodo lo rileva e accorcia l'intervallo per quel percorso.

### 9.6 La porta in ascolto: cosa espone e come è protetta (D-14)

Per essere contattato, un nodo deve avere un socket UDP in ascolto raggiungibile dall'esterno (porta mappata, IPv6 aperto o varco di hole punching). Non è specifico delle chiamate: è lo stesso socket per tutto, aperto finché l'app gira. Il riferimento è WireGuard, che tiene una porta UDP aperta in permanenza su milioni di macchine ed è considerato tra i software di rete più sicuri: il filtro silenzioso (D-14, §8.3) porta lo stesso comportamento davanti a QUIC. Quello che conta non è che la porta sia aperta, ma **quanto codice raggiunge chi non è autorizzato** e **cosa gli risponde**.

**Cosa vede un estraneo.** Niente. Il nodo non risponde mai a un pacchetto che non supera i controlli: nessun errore, nessun rifiuto, nessuna risposta più grande della richiesta. Dietro NAT la porta è indistinguibile da una porta chiusa; su IPv6 diretto una scansione può al massimo dedurre che "qualcosa ascolta" su quella porta casuale, senza poter dire cosa.

**Cosa attraversa un pacchetto prima di arrivare al codice applicativo:**

| Passo | Costo per il nodo | Chi lo supera |
|---|---|---|
| 1. lunghezza e forma dell'header | confronti | chiunque |
| 2. quota anti-replay limitata per indirizzo sorgente | tabella bounded: max 1024 sorgenti, 4096 nonce per sorgente | credenziali gate valide |
| 3a. header corto: Connection ID con MAC valido | un hash | solo chi ha una connessione aperta |
| 3b. pacchetto iniziale: key ID noto, MAC con segreto condiviso valido e timestamp nuovo | lookup + un hash | solo chi conosce la credenziale della relazione (token invito o segreto peer) |
| 4. `quinn-proto` e handshake TLS 1.3 (`rustls`) | due DH, parsing TLS | come sopra |
| 5. chiave del peer accettata dal verificatore e primo messaggio autorizzato (amico, dispositivo dell'account, token o biglietto valido, non revocato) | ricerca locale | solo chi è autorizzato |

I passi 1–3 sono il **filtro**, l'unico codice raggiungibile da un estraneo: obiettivo ~200 righe, nessuna allocazione o stato dipendente dall'input prima della verifica MAC, fuzzing continuo in CI, prima area da sottoporre alla revisione esterna. Dopo un MAC valido lo stato anti-replay resta bounded. Un test di proprietà verifica che, per qualunque input che non supera i controlli, la macchina a stati non produca **alcuna** azione di invio.

**Rischi che restano, e quanto pesano:**

| Rischio | Dipende dalla porta aperta? | Mitigazione |
|---|---|---|
| Bug nel filtro, o in `quinn-proto`/`rustls` raggiunti da chi conosce la tua chiave | sì, è il rischio reale | filtro minimo e fuzzato; `quinn-proto` e `rustls` molto usati e fuzzati a monte (`rustls` ha avuto audit indipendenti); aggiornamenti di sicurezza tempestivi; revisione esterna (R-09) |
| Chi ti parla vede il tuo IP | no: è vero in qualunque sistema P2P, anche senza porte mappate | "nascondi il mio IP" via relay di fiducia, tipicamente il proprio computer di casa (§17.2) |
| Inondazione di traffico verso il tuo IP | no: si può inondare qualunque IP noto, con o senza porta aperta | il nodo scarta in fretta senza rispondere; la banda saturata resta un problema dell'operatore di rete |
| Un amico o un dispositivo compromesso raggiunge il codice post-autenticazione | no | fuzzing anche dei parser post-autenticazione, limiti per peer, revoca |
| Implementazione UPnP difettosa del router | parzialmente | PCP/NAT-PMP prima di UPnP; mai chiedere di attivarlo; una sola porta UDP con lease breve |

**Perché "Solo in uscita" non è automaticamente più sicura.** Senza porta mappata il nodo resta contattabile tramite i varchi di hole punching, che dietro un NAT restrittivo accettano pacchetti solo dal peer previsto: la superficie esposta a Internet si riduce ancora. In cambio, più connessioni passano da relay, e ogni relay vede chi parla con chi, quando e quanto (§11.3). La modalità *Automatica* espone una porta silenziosa ma riduce i metadati in mano a terzi; *Solo in uscita* fa il contrario. Per questo è una scelta dell'utente, spiegata nelle impostazioni, e la combinazione consigliata per chi vuole il massimo è: portatile in *Solo in uscita* con "nascondi il mio IP" attivo, computer di casa in *Automatica* come relay personale.

---

## 10. Scoperta degli indirizzi

Gli indirizzi IP domestici cambiano. Il link di invito serve solo per il primo contatto; dopo, i nodi si ritrovano così.

### 10.1 Record indirizzi cifrato

Ogni dispositivo dell'account X invia ai propri contatti, periodicamente e a ogni cambio, un **AddressRecord**:

```
AddressRecord {
  account_id, device_id, seq, expires_at,
  candidates: [...],
  relays: [device_id ...],   // propri dispositivi o amici tramite cui è raggiungibile ora
  sig                        // firmato da DK (il DeviceCert lo lega a IK_X)
}
```

Il record viene **cifrato** con una chiave derivata dal segreto di scoperta `D_X`, che conoscono solo gli amici di X e i suoi dispositivi:

```
epoch      = floor(unix_time / 3600)
lookup_key = BLAKE3("tc-lookup" ‖ D_X ‖ device_id ‖ epoch)
enc_key    = HKDF(D_X, "tc-record" ‖ epoch)
blob       = AEAD(enc_key, AddressRecord)
```

Chi non è amico di X vede solo un identificativo opaco che cambia ogni ora e un blob indecifrabile.

### 10.2 Gossip tra amici

- X invia il blob a tutti i suoi amici connessi.
- Ogni nodo conserva i blob che riceve (piccoli, con scadenza) e li **serve a chiunque chieda** con la `lookup_key` giusta. Siccome solo gli amici di X sanno calcolarla, di fatto la risposta va solo a loro.
- Quando Alice cerca Bob, chiede ai propri amici connessi `Lookup(lookup_key)` per ciascun dispositivo della `DeviceList` di Bob. Se Alice e Bob hanno un amico in comune online, Alice trova Bob.
- I propri dispositivi si ritrovano allo stesso modo, e sono i primi a cui chiedere: il computer di casa sempre acceso conosce l'indirizzo attuale di tutti gli altri dispositivi dell'account.
- I blob sono conservati e serviti **solo da amici**, mai da sconosciuti: nessun dato esce dalla cerchia di fiducia (G-11).

### 10.3 Niente DHT pubblica

La 0.1 proponeva di pubblicare il blob cifrato sulla DHT Mainline di BitTorrent per i casi in cui due amici non hanno nessun amico comune online. È **scartata**: anche cifrato e con identificativi che cambiano ogni ora, sarebbe un dato dell'utente scritto su una rete pubblica, visibile e conservabile da chiunque (G-11). Quei casi si coprono con il proprio dispositivo sempre acceso (§6.4), con un'àncora di un amico (§19.4) o con un nuovo link di invito con indirizzi aggiornati.

### 10.4 Rete locale

Beacon multicast UDP sulla LAN (gruppo `ff02::…` e `239.…`) contenente solo una `lookup_key` per epoch: due amici, o due propri dispositivi, sulla stessa rete Wi-Fi si trovano senza uscire su Internet.

Anche un identificativo opaco permette, a chi è sulla stessa rete, di notare che "c'è un nodo Loquere" e di riconoscerlo per un'ora. Per questo il beacon è attivo **solo sulle reti che l'utente ha indicato come fidate** (casa, ufficio); su reti sconosciute (bar, hotel, aeroporto) è spento. Il collegamento di un nuovo dispositivo (§6.4) può attivarlo temporaneamente, per 10 minuti, con conferma.

---

## 11. Overlay mesh e relay

### 11.1 Concetti

- **Peer table:** per ogni nodo noto (amici, partecipanti di chiamate in corso) il nodo mantiene sessione, percorsi possibili e metriche (RTT, perdita, jitter, banda stimata, stabilità).
- **Percorso:** `diretto` oppure `via R` (un relay) oppure, al massimo, `via R1 → R2` (due relay). Oltre i due salti la latenza diventa inadatta alla voce.
- **Circuito relay:** un canale logico attraverso un relay, identificato da un `circuit_id`.

### 11.2 Chi può fare da relay

Ogni nodo annuncia agli amici la propria **RelayCapability**:

```
RelayCapability {
  willing: bool,
  reachability: Public | PortMapped | Ipv6Open | NatOnly,
  max_kbps: u32,        // limite configurato dall'utente
  max_circuits: u16,
  on_battery: bool,
  metered: bool         // rete a consumo
}
```

**D-06.** Politica predefinita:
- un nodo fa da relay **solo per circuiti in cui almeno un estremo è un suo amico o un dispositivo del suo stesso account**;
- i dispositivi dello stesso account sono **sempre** relay ammessi l'uno per l'altro, con limiti propri (predefinito: senza tetto di banda sul fisso di casa) e precedenza sui relay degli amici, perché non espongono metadati a terzi;
- un nodo a batteria o su rete a consumo **non** fa da relay (vale anche per i propri dispositivi: il portatile fuori casa non fa da relay al fisso);
- limite di banda predefinito per il relay: **2 Mbit/s** in totale, regolabile;
- l'utente può disattivare completamente il relay, o all'opposto offrirlo anche agli amici degli amici (opt-in).

### 11.3 Doppia cifratura

```
Alice ══[QUIC Alice↔R]══▶ R ══[QUIC R↔Bob]══▶ Bob
          dentro: DATAGRAM RELAY{circuit_id, pacchetto QUIC E2E Alice↔Bob}
```

Alice e Bob hanno una **loro** connessione QUIC, i cui pacchetti viaggiano dentro i datagrammi delle connessioni con il relay: il relay vede solo `circuit_id`, dimensione e tempi. Sovraccarico: circa 50 byte per pacchetto, accettabile anche per l'audio. Siccome un pacchetto iniziale QUIC deve essere di almeno 1200 byte, il percorso verso il relay deve reggere datagrammi di ~1300 byte: vero su quasi tutte le reti (MTU 1500), da verificare con la scoperta della MTU (R-16).

Cosa vede il relay (documentato all'utente): gli indirizzi IP di Alice e Bob, il fatto che comunichino, il volume e i tempi del traffico. Non vede contenuti.

### 11.4 Scelta del percorso

Per ogni coppia di nodi che deve comunicare:

1. si tentano in parallelo i candidati diretti (§9) e almeno un relay candidato (gli amici comuni con la miglior `reachability`);
2. si usa il primo percorso funzionante, poi si continua a sondare gli altri;
3. si passa a un percorso migliore se il suo punteggio supera quello attuale di almeno il 20 % per 5 s consecutivi (isteresi, per evitare oscillazioni);
4. per l'**audio** con perdita > 5 % sul percorso migliore, si può inviare **in duplicato su due percorsi** (l'audio costa poca banda; il duplicato viene scartato in ricezione dal numero di sequenza).

Punteggio di un percorso:

```
score = rtt_ms + 4 × jitter_ms + 300 × loss_ratio + penalità_relay (20 ms per salto)
        (più basso è meglio)
```

---

## 12. Chiamate: segnalazione e topologie

### 12.1 Avvio di una chiamata

1. Il chiamante A crea `Call { call_id (128 bit casuali), created_by: A, invited: [B, C, D], media: audio|video, sig_A }` e una **chiave di chiamata** `K_call`.
2. Manda a ciascun invitato, sulle sessioni esistenti (dirette o via relay), un `CallInvite` con `Call` e `K_call`. L'invito va a **tutti i dispositivi online** di ciascun account invitato (§6.4).
3. Chi accetta (il primo dispositivo che risponde, per ciascun account) si collega agli altri partecipanti; gli altri dispositivi dello stesso account smettono di squillare.
4. **L'audio parte subito** con un host provvisorio (§13.5): non si aspetta l'elezione.

### 12.2 Partecipanti che non sono amici tra loro

In una chiamata di gruppo B e C possono non essere amici. Il `Call` firmato da A, con la lista dei partecipanti, vale come **biglietto**: per la durata della chiamata un nodo accetta handshake (`CallJoin{call_id}`) dai nodi elencati, anche se non sono suoi amici. Alla fine della chiamata l'autorizzazione decade. Per trovarsi, B e C usano A (o l'host) come coordinatore di hole punching e, se serve, come relay.

### 12.3 Topologie

| Modo | Come funziona | Quando |
|---|---|---|
| **Diretto** | 1:1, ciascuno manda all'altro | sempre per 1:1 |
| **Mesh** | ognuno manda i propri flussi a tutti gli altri | gruppi piccoli (≤ 4) in cui tutti hanno banda in uscita sufficiente; minima latenza, nessun punto singolo di guasto |
| **Stella (host)** | ognuno manda i propri flussi **una volta** all'host; l'host li inoltra agli altri (SFU) | gruppi più grandi, o quando qualcuno ha poca banda in uscita |
| **Stella con host esterno** | come sopra, ma l'host è un nodo amico **non partecipante** con ottima connettività (es. un nodo àncora) | quando nessun partecipante è adatto (fase successiva, M6) |

Esempio di costo in banda in uscita, video a 1 Mbit/s, 6 partecipanti:
- mesh: ciascuno invia 5 × 1 = **5 Mbit/s** (insostenibile per molte connessioni domestiche);
- stella: i partecipanti inviano **1 Mbit/s**, l'host invia fino a 5 × 5 = **25 Mbit/s** (con simulcast molto meno, §14.3).

La scelta della topologia fa parte della stessa decisione dell'elezione dell'host (§13): il risultato è un **piano di topologia**.

### 12.4 Crittografia dei media indipendente dall'host (D-07)

**D-07.** I frame audio e video sono cifrati **end-to-end a livello di frame** con chiavi derivate da `K_call` (schema analogo a SFrame, RFC 9605):

```
sender_key = HKDF(K_call, "tc-media" ‖ sender_device_id ‖ key_epoch)
frame      = header_in_chiaro ‖ AEAD(sender_key, payload)
header_in_chiaro = { stream_id, layer, seq, timestamp, keyframe, audio_level }
```

Conseguenze:
- l'host inoltra i frame **senza decifrarli**: legge solo l'intestazione per scegliere cosa mandare a chi;
- un **cambio di host non richiede un nuovo scambio di chiavi**;
- un nodo **esterno** può fare da host senza poter ascoltare la chiamata;
- l'host non può mixare l'audio (non lo decifra): il mix avviene in ricezione.

**Rinnovo chiavi:** quando qualcuno entra, chi ha avviato la chiamata (o l'host, se A è uscito) genera un nuovo `K_call` e lo distribuisce sulle sessioni pairwise; quando qualcuno esce, idem, così chi è uscito non può più decifrare (`key_epoch++`).

L'intestazione in chiaro rivela all'host chi sta parlando (`audio_level`) e la struttura dei flussi. È un compromesso accettato e documentato: serve per selezionare gli oratori attivi nelle chiamate grandi.

---

## 13. Elezione dell'host e cambio dinamico

Questa è la parte centrale richiesta. L'obiettivo: **in ogni momento, l'host è il nodo che minimizza la latenza peggiore tra i partecipanti, rispettando i vincoli di banda, con il minor numero possibile di cambi.**

### 13.1 Metriche raccolte

Ogni partecipante `i` invia ogni **2 s** all'host corrente (e, in modo mesh, a tutti) un `MetricsReport`:

| Campo | Fonte |
|---|---|
| `rtt[i][j]`, `loss[i][j]`, `jitter[i][j]` per ogni altro partecipante `j` | `PING/PONG` sui percorsi verso ciascuno, anche quelli non usati per i media |
| `path_kind[i][j]` | diretto / 1 relay / 2 relay |
| `up_kbps[i]`, `down_kbps[i]` | stima del congestion control (§14.4) più sonde attive (§13.2) |
| `power[i]` | rete elettrica / batteria con percentuale |
| `cpu_headroom[i]` | percentuale di CPU libera mediata |
| `metered[i]` | rete a consumo |
| `stability[i]` | cambi di percorso e perdite di sessione negli ultimi 5 minuti |
| `reachability[i]` | pubblico / porta mappata / IPv6 / solo NAT |

### 13.2 Stima della banda in uscita

Un partecipante che non è host invia solo i propri flussi, quindi la sua banda reale è sconosciuta. Per i **2–3 migliori candidati** (secondo RTT e raggiungibilità) l'host chiede periodicamente una **sonda di banda**: una breve raffica di pacchetti di riempimento (packet train, ~300 ms, ogni 60 s, solo se la chiamata è stabile) verso più destinatari; dalla dispersione degli arrivi si stima la capacità. La sonda è limitata per non degradare l'audio in corso.

### 13.3 Funzione di costo

Per ogni candidato host `h` e per ogni topologia ammissibile:

**Vincolo di fattibilità** (stella):

```
uscita_richiesta(h) = Σ_j Σ_{flussi s inoltrati a j} bitrate(s)  +  propri flussi
fattibile(h)        = uscita_richiesta(h) ≤ 0.8 × up_kbps[h]
                    ∧ cpu_headroom[h] ≥ 20 %
                    ∧ per ogni j: esiste un percorso h↔j con loss < 10 %
```

**Costo:**

```
lat(i, j via h) = owd(i, h) + owd(h, j) + t_inoltro          (owd ≈ rtt/2)

costo(h) =   max_{i≠j} lat(i, j via h)                         ← latenza peggiore (domina)
           + 0.3 × media_{i≠j} lat(i, j via h)
           + 50 ms × #percorsi_via_relay(h)
           + 200 ms se power[h] = batteria < 30 %
           +  80 ms se power[h] = batteria ≥ 30 %
           + 100 ms se metered[h]
           +  20 ms × stability[h]
```

Per la **mesh** il costo è `max_{i≠j} owd(i, j)` con vincolo `uscita_richiesta(i) ≤ 0.8 × up_kbps[i]` per **ogni** `i`.

Il **piano di topologia** scelto è quello di costo minimo tra tutti quelli fattibili. Se nessuno è fattibile, si abbassa il profilo media (strati video più bassi, poi solo audio per alcuni flussi) e si ricalcola.

### 13.4 Chi decide e come si evita il "cervello diviso"

**D-08.** Decide **l'host corrente** (che riceve già tutte le metriche). Non serve consenso distribuito: serve solo un ordine non ambiguo.

- Lo stato della chiamata ha un **epoch** (intero crescente).
- L'host pubblica `TopologyPlan { epoch, mode, host, succession: [h2, h3, h4], switch_at, sig_host }`.
- La **lista di successione** (i successivi tre migliori candidati) è nota a tutti in anticipo.
- Regola di precedenza: tra due piani vince quello con `(epoch, hash(host ‖ call_id))` più alto. Due metà di una chiamata separate da un guasto di rete, quando si ritrovano, convergono così sul piano vincente.
- Ogni partecipante può **ricalcolare** il piano dalle metriche ricevute; se la sua valutazione differisce molto (es. l'host dichiara una banda falsa), lo segnala nei log e nell'ispettore di rete. In v1 non c'è voto di sfiducia: ricalcolo e segnalazione sono sufficienti.

### 13.5 Host iniziale

All'avvio non ci sono metriche. Host provvisorio:
1. il partecipante con la migliore `reachability` dichiarata, a parità
2. quello con più connessioni dirette già attive verso gli altri, a parità
3. il chiamante.

Dopo **5 s** di metriche avviene la prima elezione vera, che può confermare o cambiare l'host.

### 13.6 Quando cambiare host (isteresi)

Si cambia host solo se vale **una** di queste condizioni:

| Condizione | Soglia iniziale |
|---|---|
| Il nuovo candidato è nettamente migliore, in modo stabile | `costo(nuovo) < 0.75 × costo(attuale)` per 10 s consecutivi |
| L'host attuale è in sovraccarico | perdita in uscita > 5 % per 3 s, o `uscita_richiesta > up_kbps` |
| L'host attuale si sta disconnettendo | annuncio esplicito (`HostLeaving`), batteria critica, chiusura dell'app |
| L'host attuale non risponde | 3 heartbeat mancati (heartbeat ogni 250 ms → ~750 ms) |

E comunque: **almeno 30 s** tra due cambi pianificati (non vale per guasti).

### 13.7 Cambio pianificato: "make-before-break"

```
 t-1.0 s  Host H1 pubblica TopologyPlan{epoch+1, host=H2, switch_at=t}
 t-1.0 s  Tutti aprono/verificano la sessione con H2 e iniziano a
          inviare i propri flussi a ENTRAMBI H1 e H2 (doppio invio)
 t-0.5 s  H2 inizia a inoltrare; i mittenti video producono un keyframe
          (H2 non ha ancora il contesto dei flussi)
 t        I riceventi passano ad ascoltare H2 (jitter buffer unico,
          deduplicazione per seq: nessun buco udibile)
 t+0.5 s  I mittenti smettono di inviare a H1
 t+3.0 s  H1 smette di inoltrare (timeout di sicurezza)
```

Il doppio invio dura ~1,5 s e costa banda solo ai mittenti; l'audio non ha interruzioni perché il jitter buffer in ricezione deduplica.

### 13.8 Cambio per guasto dell'host

1. Ogni partecipante rileva i 3 heartbeat mancati.
2. Il primo della lista di successione `h2`, se vivo, si proclama host con `epoch+1` e inizia subito a inoltrare.
3. Tutti, appena rilevato il guasto, iniziano a inviare a `h2`. Se `h2` non risponde entro 500 ms, si passa a `h3`.
4. I video ripartono dal primo keyframe richiesto; l'audio riprende appena arriva al nuovo host (obiettivo < 1,5 s).

### 13.9 Host esterno (fase M6)

Se nessun partecipante è adatto (es. tutti su connessione mobile), il piano può nominare un **nodo amico non partecipante** che abbia dichiarato `RelayCapability` sufficiente. Grazie a D-07 non può decifrare i media. Richiede il consenso del nodo esterno (`HostOffer` / `HostAccept`) e rispetta i suoi limiti di banda.

### 13.10 Chiamate grandi: oratori attivi

Oltre ~8 partecipanti audio, l'host inoltra a ciascuno solo i **3 flussi con `audio_level` più alto** (più quello eventualmente fissato dall'utente), riducendo banda e carico di decodifica.

---

## 14. Pipeline media

### 14.1 Audio

```
Microfono → [ring RT] → AEC (cancellazione eco) → soppressione rumore → AGC
          → VAD → Opus (encoder) → cifratura frame → pacchetti
Pacchetti → decifratura → jitter buffer adattivo (per mittente) → Opus decoder
          (con PLC/FEC) → mix → [ring RT] → altoparlanti
                                   └──────▶ riferimento per l'AEC
```

| Parametro | Valore iniziale |
|---|---|
| Frequenza di campionamento | 48 kHz |
| Durata frame Opus | 20 ms (10 ms in modalità bassa latenza) |
| Bitrate voce | 24–32 kbit/s mono, VBR; modalità musica 64–96 kbit/s opzionale |
| FEC in banda | attiva quando la perdita stimata > 2 % |
| DTX | attiva (nessun pacchetto nei silenzi, solo comfort noise) |
| Jitter buffer | adattivo 20–200 ms, obiettivo 40 ms |
| Push-to-talk, muto, soppressione rumore on/off | sì |

**Codec:** Opus. **D-09.** Usare un'implementazione **in Rust puro** di Opus (`opus1`, già `opus-rs`), che dichiara zero dipendenze e prestazioni comparabili a libopus; fallback: libopus vendorizzato in C se i test di conformità e ascolto falliscono (R-05).

**Elaborazione voce (AEC, rumore, guadagno):** **D-10.** Usare `sonora`, port in Rust puro della pipeline di elaborazione audio di WebRTC (AEC3, noise suppression, AGC2). È giovane (versione 0.1): va validata presto con test d'ascolto reali (R-06). Alternativa per il solo rumore: `nnnoiseless` (RNNoise in Rust).

### 14.2 Video

```
Webcam → conversione colore/scala → encoder (simulcast 2–3 strati) → cifratura frame
       → pacchettizzazione (frammentazione ≤ 1200 B) → NACK/ritrasmissione → rete
```

| Parametro | Valore iniziale |
|---|---|
| Risoluzioni simulcast | 180p · 360p · 720p (720p solo se la banda lo consente) |
| Frame rate | 15–30 fps adattivo |
| Bitrate | 150 kbit/s · 500 kbit/s · 1,5 Mbit/s |
| Keyframe | su richiesta (nuovo ricevente, cambio host, perdita) e ogni 10 s |
| Recupero perdite | NACK con ritrasmissione dalla **cache dell'host** (ultimo ~1 s per flusso) |

**Codec: AV1 e H.264 con negoziazione (D-17).**

| Codec | Pro | Contro |
|---|---|---|
| **AV1**: encoder `rav1e` o hardware, decoder `rav1d` | libero da royalty, ottima efficienza, scalabilità temporale nativa (SVC) utile all'host, decoder in Rust con prestazioni vicine a dav1d | codifica software pesante: in tempo reale probabilmente solo a risoluzioni basse su CPU modeste; encoder hardware AV1 solo su GPU recenti |
| **H.264**: encoder hardware, decoder in Rust puro dell'ecosistema o hardware | encoder hardware su quasi tutti i computer degli ultimi dieci anni, decodifica leggera | nessun encoder software in Rust puro (OpenH264 è C), questioni di brevetti in alcune giurisdizioni (R-13) |

**D-17.** Regole di negoziazione:

- **Ogni nodo sa decodificare entrambi** (decoder software sempre presenti, hardware quando disponibili). Quindi in una chiamata di gruppo non serve trovare un codec comune a tutti: la negoziazione riguarda solo la **codifica**, e ciascun mittente sceglie per sé.
- Ordine di preferenza del mittente: AV1 hardware → H.264 hardware → AV1 software (`rav1e`, massimo 360p). Nessun encoder H.264 software in v1.
- I riceventi annunciano nel `CallJoin` le proprie preferenze di decodifica (es. "ho il decoder H.264 hardware, preferisco H.264 per risparmiare batteria"); il mittente ne tiene conto se non gli costa qualità.
- Un mittente può cambiare codec durante la chiamata, solo su un keyframe.
- L'identificativo del codec sta **dentro** il payload cifrato: l'host non ha bisogno di saperlo e non lo vede.

Il benchmark di M4 su un portatile di fascia media di 4 anni fa non è più un go/no-go, ma serve a tarare le preferenze predefinite e la risoluzione massima di `rav1e`.

**Cattura:** binding diretti alle API di sistema (AVFoundation su macOS, Media Foundation su Windows, V4L2 su Linux/FreeBSD), dentro `loquere-devices`.

**Rendering:** texture `wgpu` dentro egui; conversione YUV→RGB in shader.

### 14.3 Selezione degli strati da parte dell'host

Ogni ricevente comunica all'host quali partecipanti sta guardando e a che dimensione (griglia, oratore in primo piano, miniatura) e la propria banda in ingresso stimata. L'host sceglie per ciascun ricevente lo strato più alto che rientra nella sua banda e che ha senso per la dimensione a schermo. Questo è il motivo per cui un host con simulcast costa molto meno della moltiplicazione ingenua di §12.3.

### 14.4 Congestion control

Per ogni connessione, un controllo del bitrate combinato **ritardo + perdita** (concettualmente simile al GCC di WebRTC, semplificato):
- lavora **sopra** il controllo di congestione di QUIC (§8.4) e serve a scegliere il bitrate degli encoder: meglio abbassare la qualità che lasciare a QUIC il compito di accodare o scartare datagrammi;
- il ricevente restituisce periodicamente (messaggio `MediaFeedback` sullo stream di controllo, ogni 50–100 ms) tempi di arrivo per numero di sequenza;
- il mittente stima il **gradiente del ritardo**: se cresce, la coda nel router si sta riempiendo → riduce il bitrate prima che arrivino le perdite;
- con perdita > 10 % riduzione moltiplicativa, con perdita < 2 % e ritardo stabile aumento graduale;
- **priorità di allocazione**: audio > video strato basso > strati alti > file.

La stima di banda alimenta sia gli encoder sia l'elezione dell'host (§13.1).

### 14.5 Sincronizzazione

Timestamp media per flusso e un orologio di riferimento per mittente (scambiato nel controllo) per allineare audio e video dello stesso partecipante (lip sync, tolleranza ±40 ms).

---

## 15. Chat testuale e file

### 15.1 Modello

- **Conversazione:** 1:1 o gruppo persistente (diverso da una chiamata). Un gruppo ha un `group_id`, un elenco membri firmato dagli amministratori e un nome.
- **Messaggio:**

```
Message {
  id:        Blake3(contenuto canonico),
  conv_id,
  author:    account_id,
  device:    device_id,    // dispositivo che l'ha scritto
  lamport:   u64,
  parents:   [id ...],     // "teste" note all'autore: forma un DAG
  sent_at:   timestamp (solo informativo),
  body:      Text | Edit{target} | Delete{target} | Reaction{target, emoji}
           | FileOffer{hash, size, name} | System{...},
  sig:       firma del dispositivo (DK, legato all'account dal DeviceCert)
}
```

L'ordine di visualizzazione è dato da `(lamport, id)`: deterministico su tutti i nodi anche se i messaggi arrivano in ordine diverso.

### 15.2 Sincronizzazione

Quando due membri di una conversazione si collegano, si scambiano le **teste** del DAG; ciascuno chiede gli id mancanti risalendo i `parents`. È lo stesso principio di Git: semplice, robusto alle partizioni, nessun server.

### 15.3 Consegna differita

- **1:1:** il messaggio resta nella coda in uscita del mittente finché almeno un dispositivo del destinatario non è online insieme a lui, oppure finché non lo accetta una casella postale.
- **Gruppi:** qualunque membro online che abbia il messaggio lo passa a chi rientra. Più membri ci sono, più la consegna è affidabile.

**Casella postale (v1, D-18).** Un nodo sempre acceso conserva messaggi cifrati per un destinatario che è offline, senza poterli leggere, e glieli consegna quando torna:

- la offrono i **propri dispositivi** (il fisso di casa custodisce i messaggi per il portatile e riceve per conto dell'account) e, se lo consentono, **amici** e àncore, solo per i propri amici;
- conservazione predefinita **30 giorni**, configurabile da chi offre la casella; il mittente può chiedere una scadenza più breve, mai più lunga;
- quota per amico (predefinita 50 MiB) e niente file grandi: per quelli resta l'offerta di file (§15.5);
- il messaggio viene cancellato appena il destinatario conferma la ricezione;
- cosa vede chi la ospita (documentato all'utente): mittente, destinatario, ora e dimensione. Non il contenuto. Per questo la casella preferita è sempre un proprio dispositivo, poi un amico comune.

Stati mostrati: inviato · consegnato · letto (le conferme di lettura si possono disattivare).

### 15.4 Cifratura

- In transito: sempre dentro connessioni QUIC/TLS 1.3 (forward secrecy per connessione).
- Messaggi conservati presso terzi (casella postale, membri di un gruppo che fanno da tramite): cifrati per il destinatario o per il gruppo.
- **MLS** (RFC 9420) per **tutte** le conversazioni, 1:1 comprese, tramite la crate `openmls` (**D-16**). Con più dispositivi per account anche una 1:1 è un gruppo (i dispositivi di Alice più quelli di Bob), e MLS gestisce esattamente questo: ogni dispositivo è una foglia, aggiungere o revocare un dispositivo è un'operazione del gruppo. In più dà **forward secrecy** e **sicurezza post-compromissione**: dopo un aggiornamento delle chiavi, chi aveva rubato lo stato di un dispositivo non legge i messaggi successivi.
- Suite MLS: `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`, coerente con le primitive del resto del progetto.

**Ordine dei commit senza server.** MLS presuppone un servizio che ordini i *commit* (le modifiche al gruppo) uno per epoch. Senza server:

- i commit viaggiano come messaggi del DAG (§15.2); possono farli gli amministratori del gruppo e, per i propri dispositivi, l'account interessato; gli altri membri inviano solo *proposte*;
- due commit concorrenti sulla stessa epoch: vince quello con hash minore, deterministico su tutti i nodi; chi aveva applicato il perdente torna allo stato dell'epoch precedente (conservato per 7 giorni) e applica il vincente; le proposte perse vengono ripresentate;
- dopo una partizione più lunga della finestra, il lato perdente rientra con un *external commit* o viene riaggiunto da un amministratore (R-11).

### 15.5 File

Divisi in blocchi da 64 KiB, verificati con BLAKE3 in streaming, trasferimento riprendibile, su canale affidabile dedicato. I relay possono rifiutare i trasferimenti grandi (flag nella `RelayCapability`). Le immagini piccole mostrano un'anteprima.

---

## 16. Persistenza locale

Percorsi coerenti con le altre Crafting Apps:

| OS | Cartella |
|---|---|
| Linux / FreeBSD | `$XDG_CONFIG_HOME/Loquere/` (default `~/.config/Loquere/`) |
| macOS | `~/Library/Application Support/Loquere/` |
| Windows | `%APPDATA%\Loquere\` |

```
Loquere/
├── identity.tck          # IK (solo dispositivi Admin), DK, D, cifrati con MK
├── profile.bin           # profilo firmato
├── devices.log           # DeviceList e cronologia delle revoche
├── contacts.log          # amici, chiavi, segreti di scoperta (cifrato)
├── invites.log           # inviti attivi e revocati
├── mls/<conv_id>.state   # stato MLS per conversazione (cifrato)
├── conversations/<conv_id>/segment-000001.log   # log append-only cifrati
├── mailbox/              # messaggi custoditi per altri, con scadenza (§15.3)
├── files/<blake3>        # allegati
├── peers.cache           # ultimi indirizzi e metriche noti (accelera il riavvio)
├── settings.toml
└── logs/                 # come SoundCraft: tetto 16 MiB, livello da RUST_LOG
```

**D-11.** Nessun database esterno: **log append-only a segmenti** con indice in memoria ricostruito all'avvio e snapshot periodici. Ogni record è cifrato singolarmente con una chiave derivata da `MK` (§6.1). Semplice, robusto ai crash (un record troncato in coda si scarta), nessuna dipendenza. Alternativa se gli indici diventano complessi: `redb` (Rust puro).

**D-25. Framing del log locale.** Ogni record è `lunghezza (u32 little-endian) ‖ SealedBox-v1`; massimo 16 MiB ciphertext per record. I dati associati AEAD sono `loquere:store-record:v1\0 ‖ seq(u64 little-endian)`, dove `seq` è l'ordine del record dal valore zero. All'avvio una coda con header/ciphertext incompleto viene troncata all'ultimo record valido; lunghezze impossibili e tag non validi sono errori, non vengono scartati come se fossero crash.

**D-26. Prefisso del filtro silenzioso (superato da D-32).** Il formato corrente è definito da D-32: timestamp u64 BE, key ID opaco a 16 byte e MAC keyed BLAKE2s a 16 byte; anti-replay limitato a 1024 sorgenti e 4096 pacchetti validi per sorgente.

**D-27. Simulatore deterministico.** `loquere-sim` usa un generatore SplitMix64 con seed esplicito (solo test, mai per segreti) e link diretti configurabili con latenza, jitter uniforme, perdita, banda e partizioni. Pacchetti consegnati sono ordinati per tempo e sequenza di invio; nessun socket o clock di sistema.

**D-28. Token di Retry QUIC.** La chiave server casuale è mantenuta solo in memoria; per ogni contesto Quinn ricava una chiave con HKDF-SHA256 e label `loquere:quic-retry-token:v1`, poi cifra i token con ChaCha20-Poly1305 e nonce casuale. La sorgente temporale per la scadenza dei token è iniettata nella configurazione server.

**D-29. Driver QUIC sans-IO.** `QuicNode` incapsula `quinn-proto::Endpoint` e le connessioni; riceve datagrammi già filtrati, tempo monotono e indirizzi dal chiamante, e restituisce datagrammi/eventi senza aprire socket o leggere clock di sistema. La scelta e la gestione dei socket UDP restano fuori da `loquere-wire`.

**D-30. Eventi di trasporto verso l'engine.** Il driver non interpreta gli eventi applicativi di QUIC: consegna allo strato superiore notifiche di stream e datagrammi, oltre a connessione stabilita/persa. Una connessione persa viene rimossa dalla tabella interna dopo aver consumato gli eventi terminali.

**D-31. Metadati UDP QUIC.** Il driver conserva su ogni `Transmit` destinazione, IP sorgente richiesto, ECN e segmentazione GSO; i metadati ECN ricevuti sono passati a `quinn-proto`. Il layer socket applica questi suggerimenti quando supportati dal sistema operativo e dal percorso.

**D-32. Credenziale segreta del filtro.** Il MAC pre-autenticazione non usa più il DeviceId pubblico come chiave. Ogni relazione usa un segreto casuale condiviso; il token segreto dell'invito lo inizializza al primo contatto e viene conservato alla successiva accettazione. Il prefisso porta un key ID opaco per selezionare la credenziale locale; la chiave MAC è derivata con HKDF-SHA256 e domain separation sul DeviceId destinatario.

**D-33. Demultiplexing UDP pre-QUIC.** `loquere-net` rimuove il prefisso solo quando il payload dopo i 40 byte è un QUIC v1 Initial; gli Initial scaduti o con MAC non valido vengono comunque inviati al controllo gate e scartati, senza euristiche sull'orario per riconoscere il prefisso. Gli altri pacchetti passano solo se il destination CID è un CID locale autenticato. Nessun socket o invio è implementato da questo filtro.

**D-34. Adapter UDP portabile iniziale.** `UdpSocketAdapter` usa `std::net::UdpSocket` bloccante, buffer ricezione del chiamante e timeout configurabile nel thread `net`. Initial QUIC non possono essere inviati senza prefisso: `send_gate_initial` verifica il key ID e applica il MAC; gli altri pacchetti usano `send`. ECN, GSO o override IP sorgente non applicabile sono errori espliciti, mai ignorati; ECN può essere ignorato solo scegliendo esplicitamente `IgnoreExplicitly`. Un backend OS-specifico potrà aggiungere queste ottimizzazioni senza cambiare il filtro sans-IO.

**D-35. Composizione rete–QUIC.** `UdpQuicEndpoint` possiede adapter, filtro ingressi e `QuicNode` in un unico oggetto da assegnare al thread `net`; espone ricezione filtrata, `poll` dei timer, accesso alla macchina QUIC e invio con prefisso autenticato sugli Initial. Il chiamante continua a governare il clock e lo scheduling, così il protocollo resta testabile sans-IO.

**D-36. Key ID gate direzionale.** Un ingresso autenticato identifica il key ID locale (derivato per il dispositivo destinatario locale), ma una risposta deve usare il key ID derivato per il DeviceId remoto. `authorize_peer_secret` registra la corrispondenza per la relazione; `UdpQuicEndpoint` applica il key ID remoto alle risposte. Il mittente del primo Initial conosce già il dispositivo destinatario e fornisce direttamente la stessa credenziale.

**D-37. MLS e versione minima Rust.** Le conversazioni usano OpenMLS con la suite `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`; la crate MLS e il provider RustCrypto sono fissati alla linea 0.9/0.6. Queste versioni richiedono Rust 1.91, quindi l'MSRV workspace è aggiornata a 1.91 invece di usare una release MLS più vecchia con MSRV non dichiarata. Le chiavi Ed25519 dei messaggi MLS sono le chiavi certificate del dispositivo; storage persistente e ordinamento DAG restano responsabilità dei livelli chat/store.

**D-38. Snapshot MLS cifrati.** Lo stato del key store OpenMLS e l'identificatore del gruppo vengono salvati insieme come snapshot nel log append-only cifrato di `loquere-store`; ad ogni operazione che può mutare lo stato si accoda uno snapshot completo, e al riavvio si ripristina l'ultimo snapshot autenticato prima di caricare il gruppo con OpenMLS. La chiave del log è fornita dal livello identità (derivata dal master key locale), non viene generata né salvata da `loquere-chat`. Questa prima implementazione cresce a ogni snapshot: compattazione/rotazione del log è requisito prima dell'uso prolungato e resta da completare.

---

## 17. Sicurezza e privacy

### 17.1 Modello delle minacce

| Avversario | Cosa può fare | Contromisure |
|---|---|---|
| Osservatore di rete passivo | vede IP, tempi, volumi | tutto cifrato; nessuna identità nelle intestazioni (solo indici di sessione) |
| Sconosciuto che scansiona porte | — | porta casuale, filtro silenzioso, nessuna risposta senza conoscere la credenziale condivisa peer (D-03, D-14, §9.6) |
| Chi registra e rigioca un handshake | — | timestamp nel prefisso del filtro, 0-RTT disattivato (§8.3) |
| Dispositivo malevolo sulla LAN | finge di essere il router, ascolta i beacon | risposte UPnP solo dal gateway (D-15); beacon solo su reti fidate (§10.4) |
| Chi ha ottenuto un tuo link di invito | può mandarti una richiesta di amicizia | conferma manuale predefinita, inviti monouso e a scadenza, revoca |
| Relay (amico) | vede IP degli estremi, chi parla con chi, volumi | nessun contenuto (doppia cifratura); relay solo tra amici di default |
| Host di chiamata | vede chi parla e quando (`audio_level`), dimensioni e struttura dei flussi | nessun contenuto (D-07); se è un partecipante decifra comunque come tutti gli altri |
| Partecipante malevolo | può dichiarare metriche false per diventare host | ricalcolo indipendente e segnalazione (§13.4); eventuali penalità o voto dopo la v1 |
| Ex amico | conosceva il tuo segreto di scoperta | rotazione di `D` alla rimozione (§7.3) |
| Furto o perdita di un dispositivo | accesso al disco | chiavi e cronologia cifrate con `MK` (portachiavi o passphrase); revoca del dispositivo da un altro o dalla frase di recupero (§6.4); se era Member, l'account resta intatto; blocco dell'app dopo inattività (opzionale) |
| Malware che gira come l'utente | legge la memoria dell'app, in alcuni OS anche il portachiavi | fuori dal modello di minaccia: nessuna app di messaggistica protegge da un sistema compromesso. Mitigazione parziale: `IK` solo sui dispositivi Admin, conferma per le operazioni con `IK` |
| Chi ospita una casella postale | vede mittente, destinatario, ora, dimensione | nessun contenuto (MLS); preferenza per i propri dispositivi (§15.3) |
| Amplificazione / DoS | — | filtro silenzioso, Retry di QUIC sotto carico, limite di amplificazione 3×, limiti per sorgente |

### 17.2 Esposizione dell'indirizzo IP

In un sistema P2P chi ti parla direttamente vede il tuo IP, e da quello la città e il fornitore di connessione. È vero con o senza porte aperte (§9.6). Opzione **"nascondi il mio IP"**: il traffico passa da un relay di fiducia, che è prima di tutto **un proprio dispositivo** (il computer di casa), poi un amico scelto dall'utente. Chi ti parla vede l'IP del relay, non quello della rete da cui ti colleghi. Costo: un po' di latenza in più (tipicamente 10–40 ms).

Due livelli:
- **verso i non-amici** (partecipanti di chiamata che non conosci): **attivo di default** quando è disponibile un relay di fiducia;
- **verso tutti**: opt-in, consigliato sul portatile fuori casa.

### 17.3 Verifica delle identità

Ogni contatto ha un **numero di sicurezza** (impronta delle due identità) confrontabile di persona o via QR, come nelle app di messaggistica sicura. Utile se il link di invito è passato per un canale non fidato.

### 17.4 Igiene crittografica

- Solo primitive e protocolli da librerie consolidate e revisionate (`rustls` per TLS 1.3, `openmls` per MLS); **nessuna crittografia scritta in casa** (solo la composizione: filtro silenzioso, verificatore delle chiavi, record).
- `#![forbid(unsafe_code)]` in `loquere-wire`, `loquere-mesh`, `loquere-call`, `loquere-chat`, `loquere-identity`.
- `zeroize` sulle chiavi in memoria.
- Revisione esterna del protocollo prima della v1.0 (budget da prevedere).
- Fuzzing di tutti i parser di pacchetti e record.

---

## 18. Interfaccia (egui)

```
┌──────────────┬──────────────────────────────────────────┬──────────────┐
│ ● Alice (tu) │  # Gruppo "Laboratorio"                  │ Partecipanti │
│ ────────────│ ──────────────────────────────────────── │ ──────────── │
│ AMICI        │  Bob   10:21  ciao a tutti               │ ● Bob        │
│ ● Bob        │  Carla 10:22  arrivo tra 5 minuti        │ ○ Carla      │
│ ○ Carla      │  …                                       │ ● Dario      │
│ ● Dario      │                                          │              │
│ GRUPPI       │                                          │ [📞] [🎥]    │
│ # Laboratorio│ ┌──────────────────────────────────────┐ │              │
│ + Aggiungi   │ │ Scrivi un messaggio…           [📎] │ │              │
│   amico      │ └──────────────────────────────────────┘ │              │
└──────────────┴──────────────────────────────────────────┴──────────────┘
```

- **Schermata di benvenuto:** "Crea un account" (identità → backup frase di recupero → nome e avatar → "Il tuo link di invito" con pulsanti Copia, QR, Revoca) oppure "Collega a un account esistente" (mostra il QR da scansionare con un dispositivo Admin, poi il codice di verifica).
- **Dispositivi:** elenco dei dispositivi dell'account con ruolo, ultimo accesso e servizi offerti (relay, casella postale); collega, rinomina, revoca.
- **Aggiungi amico:** incolla link o scansiona QR (da immagine/webcam).
- **In chiamata:** griglia video adattiva, oratore attivo evidenziato, controlli muto/video/condivisione/uscita, indicatore di qualità per partecipante.
- **Ispettore di rete** (pannello opzionale, in linea con lo spirito "strumento professionale" della famiglia): chi è l'host e perché, piano di topologia, percorso verso ciascun peer (diretto / via relay), RTT, perdita, bitrate, storico dei cambi host. Utile anche per il debug e per la fiducia dell'utente.
- **Impostazioni di rete:** raggiungibilità (*Automatica* / *Solo in uscita*, con la spiegazione dei compromessi di §9.6), relay on/off e limiti, casella postale (giorni, quota), reti fidate per il beacon LAN, "nascondi il mio IP".
- Tema scuro coerente con le altre Crafting Apps; scorciatoie standard (es. `Ctrl/Cmd+Shift+M` muto, barra spaziatrice push-to-talk configurabile).

---

## 19. CLI, canale di controllo, MCP, nodo headless

### 19.1 CLI

```sh
loquere-cli id new --name "Alice"            # crea account (portachiavi o passphrase)
loquere-cli id new --name "Alice" --output identity.loq # identità cifrata con passphrase chiesta senza eco
loquere-cli id show --file identity.loq          # verifica e mostra i dati pubblici dell'account
loquere-cli device link                       # su un nuovo dispositivo: mostra il codice da approvare
loquere-cli device approve "TCL-…"            # su un dispositivo Admin: approva, mostra il codice di verifica
loquere-cli device list
loquere-cli device revoke "MacBook vecchio"
loquere-cli invite create --file identity.loq --name "Alice" --expires-in 7d # monouso, accettazione manuale
loquere-cli invite inspect "loquere://invite/…" # verifica firma e mostra i dati pubblici
loquere-cli friend add "loquere://invite/…"
loquere-cli friend list
loquere-cli send --to bob "ci sentiamo alle 18"
loquere-cli call --to bob,carla --audio
loquere-cli net status                        # candidati, NAT, relay, peer
```

### 19.2 Canale di controllo JSON

Come in SoundCraft: `loquere --control 7801` apre un canale JSON **solo su localhost**, protetto da un token scritto in un file leggibile solo dall'utente. Comandi e eventi sono gli stessi di `loquere-engine`.

```sh
loquere-cli app --port 7801 call.mute '{"muted":true}'
loquere-cli app --port 7801 net.inspect
```

### 19.3 Server MCP

Espone strumenti per agenti (leggere conversazioni, riassumere, stato rete, ecc.). **D-12.** Le azioni che contattano altre persone (inviare messaggi, avviare chiamate, accettare amicizie, condividere inviti) richiedono **sempre una conferma nell'interfaccia** dell'utente, anche se richieste via MCP.

### 19.4 Nodo headless ("àncora")

```sh
loquere-cli node --anchor --relay-kbps 20000 --mailbox-days 30
```

Stesso codice, senza interfaccia: ideale su un Raspberry Pi o un piccolo VPS. Può essere un'identità a sé oppure un **dispositivo Member del proprio account** (§6.4): in quel caso fa da relay personale e casella postale per i propri dispositivi, e da àncora per gli amici solo se lo si abilita. Non custodisce mai `IK`. Fa da coordinatore di hole punching, relay, casella postale e, in futuro, host esterno per le chiamate dei propri amici. È il modo pratico di risolvere R-01 restando fedeli al "nessun server": **è un nodo come gli altri, con un'identità propria, che fa solo ciò che i suoi amici gli chiedono.**

---

## 20. Piattaforme

| Piattaforma | v1 | Note |
|---|---|---|
| macOS 11+ (Apple Silicon e Intel) | ✅ | CoreAudio, AVFoundation, VideoToolbox; firma e notarizzazione |
| Windows 10/11 (x64, ARM64) | ✅ | WASAPI, Media Foundation; regola firewall al primo avvio |
| Linux (x86_64, ARM64) | ✅ | ALSA (e PipeWire/PulseAudio tramite ALSA), V4L2, VA-API |
| FreeBSD | ✅ | come Linux; webcam via webcamd/V4L2 |
| Android / iOS | ⏳ M7 | **Limite strutturale:** i sistemi mobili sospendono i socket delle app in background. Ricevere una chiamata con l'app chiusa richiede le notifiche push. **Servizio push opzionale**, descritto sotto. |
| Web (WASM) | ❌ | Il browser non può aprire socket UDP grezzi, quindi non può essere un nodo. Un client web richiederebbe WebRTC e un nodo desktop come ponte. Fuori ambito. |

**Push su mobile (opt-in, D-19).** Il telefono è un dispositivo Member dell'account. Il dispositivo sempre acceso dell'utente (fisso di casa o àncora) riceve chiamate e messaggi per conto del telefono e lo **sveglia** con una notifica push vuota: niente mittente, niente contenuto, solo "svegliati". Il telefono si collega poi normalmente, in P2P, e scarica tutto.

- **Android:** UnifiedPush, con un distributore scelto dall'utente (ntfy o simili, anche ospitato sul proprio nodo di casa); Firebase solo come ripiego esplicito. Nessun server del progetto.
- **iOS:** Apple consente di inviare notifiche solo a chi possiede la chiave APNs dell'app, che non si può distribuire agli utenti. Serve quindi un **gateway del progetto**, minimo e senza stato, che vede soltanto un token opaco del dispositivo e l'ora della sveglia. È l'unica eccezione a G-4, opt-in e dichiarata chiaramente all'utente.

---

## 21. Dipendenze: budget e motivazioni

**Regola:** ogni dipendenza entra solo se (a) implementarla internamente è rischioso (crittografia) o molto costoso (codec, AEC, UI), (b) è in Rust puro, oppure è un binding diretto alle API del sistema operativo, (c) ha licenza compatibile con `MIT OR Apache-2.0`. `cargo deny` in CI con lista consentita esplicita; `cargo tree` controllato a ogni PR.

| Area | Crate | Motivo | Rust puro |
|---|---|---|---|
| UI | `egui`, `eframe` (backend `wgpu`) | stesso stack delle Crafting Apps | ✅ |
| Firme | `ed25519-dalek` | identità | ✅ |
| AEAD | `chacha20poly1305` | sessioni, frame media, archiviazione | ✅ |
| Hash / KDF | `blake3`, `blake2`, `hkdf` | id messaggi e file (BLAKE3); filtro silenzioso (BLAKE2s); derivazioni | ✅ (blake3 ha SIMD opzionale) |
| Confronto tag | `subtle` | confronto in tempo costante dei tag MAC | ✅ |
| Password | `argon2` | protezione chiavi su disco | ✅ |
| Trasporto | `quinn-proto` | QUIC sans-IO, senza runtime asincrono (D-04) | ✅ |
| MLS | `openmls` + `openmls_rust_crypto` + `openmls_basic_credential` | implementazione RFC 9420 e provider RustCrypto; suite D-16/D-37 | ✅ |
| Log locale | `loquere-store` (interno) | snapshot di stato MLS cifrati e autenticati (D-11, D-25, D-38) | ✅ |
| TLS | `rustls` con provider `ring`, chiavi pubbliche grezze (RFC 7250) | handshake e cifratura del trasporto (D-05) | Rust + assembly (`ring`) |
| MLS | `openmls` + provider crittografico Rust | tutte le conversazioni (D-16); la dipendenza più pesante aggiunta nella 0.2, da controllare con `cargo tree` | ✅ |
| UPnP-IGD | `igd-next` (API sincrona) | mappatura porte (D-15) | ✅ |
| Portachiavi | binding diretti (`objc2`, `windows`); su Linux/FreeBSD `zbus` con API bloccante | custodia di `MK` (§6.1) | binding / ✅ |
| Azzeramento memoria | `zeroize` | chiavi | ✅ |
| Audio codec | `opus1` | voce | ✅ (0 dipendenze dichiarate) |
| Elaborazione voce | `sonora` | AEC3, rumore, AGC | ✅ |
| Audio I/O | `cpal` | microfono e altoparlanti | binding OS |
| Video codec | `rav1e`, `rav1d`; decoder H.264 in Rust puro dell'ecosistema; encoder hardware via API di sistema | AV1 e H.264 (D-17) | Rust + assembly / binding |
| Binding OS | `objc2` (macOS), `windows` (Windows), `libc` | cattura video, encoder HW, portachiavi | binding |
| Canale di controllo | `serde`, `serde_json` | solo per `loquere-control` | ✅ |
| Log | `log` + scrittore interno | come SoundCraft | ✅ |

**Implementati internamente** (niente crate): filtro silenzioso, verificatore delle chiavi per `rustls`, guida di `quinn-proto` dal thread `net`, controllo del bitrate dei media, jitter buffer, ring buffer RT, PCP/NAT-PMP, beacon LAN, codifica binaria dei record, archiviazione a log, ordinamento dei commit MLS, frase di recupero (lista di parole inclusa come asset), simulatore di rete.

**Esplicitamente scartati:**

| Alternativa | Perché no |
|---|---|
| `tokio` / async | non necessario con pochi socket; complica il tempo reale; molte dipendenze (D-02) |
| `libp2p` | molto ampio, molte dipendenze, astrazioni che non servono |
| `iroh` | ottimo, ma per il NAT si appoggia a server relay (pubblici o da ospitare); dipendenze pesanti (QUIC, TLS, async) |
| `webrtc-rs` | stack WebRTC completo, enorme, pensato per un server di segnalazione |
| SQLite | C, non necessario (D-11) |
| DHT Mainline (BEP 44) | pubblica dati dell'utente su una rete pubblica, anche se cifrati (G-11, §10.3) |
| Sender keys | sostituite da MLS (D-16) |
| Protocollo proprio stile WireGuard (0.1) e Noise (`snow`) | sostituiti da QUIC + TLS 1.3: meno codice di trasporto nostro |
| `quinn` (wrapper asincrono) | richiede `tokio`; `quinn-proto` dà lo stesso protocollo senza runtime (D-02) |

---

## 22. Strategia di test

1. **Unit e property test** su ogni macchina a stati sans-IO.
2. **Simulatore di rete deterministico** (`loquere-sim`): N nodi virtuali, ciascuno dietro un NAT simulato (full cone, restricted, port-restricted, simmetrico, CGNAT, solo IPv6, firewall rigido), con latenza, jitter, perdita e banda per collegamento, partizioni e ricongiungimenti, tutto con seme fisso. Scenari obbligatori in CI:
   - due nodi dietro NAT simmetrico con un amico comune raggiungibile → relay;
   - chiamata a 6 con host che perde banda a metà → cambio pianificato senza buchi audio;
   - host che sparisce di colpo → successione < 1,5 s;
   - partizione e ricongiungimento → convergenza sul piano con epoch più alto;
   - DAG di chat con messaggi concorrenti in partizione → ordine identico su tutti i nodi;
   - commit MLS concorrenti in partizione → stesso stato del gruppo su tutti i nodi dopo il ricongiungimento;
   - collegamento di un dispositivo, poi revoca → il dispositivo revocato non decifra più nulla e non completa handshake;
   - portatile dietro CGNAT in *Solo in uscita* con il fisso di casa come relay → chat, chiamate e "nascondi il mio IP" funzionano;
   - pacchetti casuali, troncati, rigiocati o senza prefisso valido → **nessuna** azione di invio (test di proprietà, §9.6).
3. **Test su rete reale:** `tc netem` su Linux, matrice di router domestici reali e un hotspot mobile (CGNAT).
4. **Qualità audio:** misura della latenza bocca-orecchio con loopback fisico; test d'ascolto per AEC e soppressione rumore su hardware reale (cuffie, altoparlanti di portatile, microfoni USB).
5. **Fuzzing** (`cargo fuzz`) di parser di pacchetti (con priorità al percorso pre-autenticazione), link di invito, codici di collegamento, record, frame, messaggi MLS.
6. **Benchmark** codec (taratura delle preferenze AV1/H.264 in M4) e consumo CPU per chiamata.

---

## 23. Roadmap

| Milestone | Contenuto | Criterio di uscita |
|---|---|---|
| **M0** Fondamenta | crypto, account e `DeviceCert` (anche con un solo dispositivo), portachiavi, link di invito, filtro silenzioso + QUIC (`quinn-proto`, `rustls` con chiavi grezze), archiviazione, simulatore | due nodi sulla stessa LAN diventano amici e si scambiano messaggi da CLI; fuzzing del percorso pre-autenticazione in CI |
| **M1** Internet | candidati, PCP/NAT-PMP/UPnP con la politica D-15, IPv6, indirizzi riflessi, hole punching via amico comune, gossip indirizzi, relay | test di simulatore su tutta la matrice NAT verdi; amici su reti diverse si ritrovano dopo un cambio di IP |
| **M2** Chat completa + UI + dispositivi | egui, MLS per tutte le conversazioni, DAG, collegamento e revoca dei dispositivi, canale dell'account, casella postale, file | uso quotidiano interno ("dogfooding") per la chat su due computer dello stesso account |
| **M3** Voce 1:1 | pipeline audio, Opus, AEC/NS/AGC, jitter buffer, congestion control, squillo su più dispositivi | latenza < 200 ms su rete domestica, qualità accettabile in test d'ascolto |
| **M4** Voce di gruppo | topologie mesh/stella, elezione host, cambio pianificato e per guasto, oratori attivi, ispettore di rete + **benchmark codec** | chiamata a 8 stabile per 1 ora con cambi host forzati; preferenze AV1/H.264 tarate |
| **M5** Video | cattura, AV1 e H.264 con negoziazione, encoder hardware, simulcast, selezione strati, NACK, keyframe | videochiamata a 6 a 360p su hardware di riferimento, con mittenti di codec diversi nella stessa chiamata |
| **M6** Àncora e host esterno | modalità `node --anchor` (anche come dispositivo Member), host non partecipante | un gruppo di amici tutti dietro CGNAT funziona grazie a un'àncora |
| **M7** Mobile | Android (UnifiedPush) poi iOS (gateway APNs), con i limiti di §20 | una chiamata sveglia il telefono con l'app chiusa |
| **v1.0** | revisione di sicurezza esterna, rilasci firmati con `SHA256SUMS.txt` | — |

---

## 24. Rischi

| ID | Rischio | Impatto | Mitigazione |
|---|---|---|---|
| R-01 | Nodi entrambi dietro NAT restrittivo senza amici raggiungibili in comune | non si connettono | IPv6, apertura porte, proprio dispositivo sempre acceso, nodo àncora; messaggio chiaro all'utente su cosa fare |
| R-02 | Esposizione dell'IP tramite link e connessioni dirette | privacy | avvisi, link senza indirizzi o che puntano al nodo di casa, "nascondi il mio IP" via relay (di default verso i non-amici) |
| R-03 | Abuso dei relay (banda) | costi e prestazioni per chi offre il relay | relay solo tra amici, limiti, mai su batteria o rete a consumo |
| R-04 | Codifica video software troppo pesante | video di bassa qualità su hardware modesto | encoder hardware AV1 o H.264, `rav1e` solo come ripiego a bassa risoluzione, benchmark in M4 |
| R-05 | Opus in Rust puro con difetti sottili | qualità audio, incompatibilità | test di conformità con i vettori ufficiali, confronto A/B con libopus, fallback vendorizzato |
| R-06 | `sonora` (AEC) immaturo | eco nelle chiamate senza cuffie | test precoci in M3, alternativa con binding a WebRTC APM (C++) come piano B, contributi upstream |
| R-07 | Oscillazione dell'host | interruzioni ripetute | isteresi, tempo minimo tra cambi, make-before-break |
| R-08 | Host che mente sulle metriche | qualità degradata | ricalcolo indipendente, segnalazione; v2 sanzioni |
| R-09 | Bug nel filtro o nelle librerie di trasporto | vulnerabilità sulla porta in ascolto | filtro di ~200 righe fuzzato (§9.6), `quinn-proto` e `rustls` aggiornati tempestivamente, `forbid(unsafe_code)` nel nostro codice, sans-IO + simulatore + revisione esterna |
| R-10 | Perdita della chiave senza backup | perdita dell'account | backup obbligatorio guidato, promemoria periodici; un secondo dispositivo collegato fa da backup |
| R-11 | MLS senza servizio di ordinamento | gruppi divergenti dopo partizioni lunghe | commit solo da amministratori, vincitore deterministico, stati di epoch conservati 7 giorni, rientro con external commit (§15.4); test nel simulatore |
| R-12 | Compromissione di un dispositivo Admin | presa dell'account | `IK` solo sui dispositivi scelti, conferma per le operazioni con `IK`, avviso agli amici sui nuovi dispositivi, revoca dalla frase di recupero |
| R-13 | Brevetti H.264 | rischi legali in alcune giurisdizioni per il decoder software | preferenza per encoder/decoder hardware del sistema (licenziati dal produttore), AV1 come preferenza predefinita; parere legale prima della v1.0 |
| R-14 | Gateway push per iOS | unico componente gestito dal progetto; metadati (token, orari) | opt-in, payload vuoto, nessuna conservazione, codice pubblico; Android senza gateway del progetto (D-19) |
| R-15 | Portachiavi debole su Linux (Secret Service leggibile da ogni processo dell'utente) | furto di `MK` da parte di malware locale | avviso nell'interfaccia, passphrase suggerita su Linux |
| R-16 | Relay di QUIC dentro QUIC su reti con MTU bassa | connessioni via relay che non si aprono | scoperta della MTU; su percorsi sotto ~1300 byte il relay inoltra i pacchetti interni senza incapsularli in un datagramma QUIC (solo con `circuit_id` autenticato) |

---

## 25. Registro delle decisioni

Tutte le domande delle revisioni sono chiuse. Questo è il riepilogo delle scelte fatte.

| Tema | Decisione | Dove |
|---|---|---|
| Nome e progetto | **Loquere**, progetto **indipendente** ispirato ad ArtCraft | intestazione, §3 |
| I/O audio | **`cpal`** | §3, §21 |
| Ring buffer lock-free | **implementazione interna** | §5.4 |
| DHT pubblica | **scartata**: niente di pubblicato da nessuna parte (G-11) | §10.3 |
| Protezione delle chiavi | **portachiavi del sistema** (predefinito) **e** passphrase; su Linux/FreeBSD tramite `zbus` | §6.1 |
| Più dispositivi | **v1**, con chiavi per dispositivo, sincronizzazione e il computer di casa come relay (D-13) | §6.4 |
| Chiave dell'account | solo sul **primo dispositivo e su quelli scelti**, mai sui nodi headless | §6.4 |
| Avviso agli amici per i nuovi dispositivi | **attivo di default**, disattivabile | §6.4 |
| Trasporto | **QUIC** con `quinn-proto` (senza runtime asincrono) e `rustls`; handshake TLS 1.3 con chiavi pubbliche grezze (D-04, D-05) | §8 |
| Porta in ascolto | **filtro silenzioso** davanti a QUIC (D-14), una sola porta UDP casuale con lease brevi (D-15) | §8.3, §9.2, §9.6 |
| UPnP-IGD | **crate** `igd-next` | §9.2 |
| Contestare un host | **ricalcolo e segnalazione**, niente voto in v1 | §13.4 |
| Codec video | **AV1 e H.264 con negoziazione** (D-17) | §14.2 |
| Casella postale | **v1**, conservazione **30 giorni configurabile** (D-18) | §15.3 |
| Cifratura delle conversazioni | **MLS** da subito, per tutte le conversazioni (D-16) | §15.4 |
| "Nascondi il mio IP" | **attivo di default** verso i non-amici, opt-in verso tutti | §17.2 |
| Mobile | **push opzionale**: UnifiedPush su Android, gateway minimo del progetto su iOS (D-19) | §20 |
| Limiti di gruppo | **16 audio / 8 video** | §2.1 |
| Nomi di crate e binari | **tutto minuscolo** (`loquere-wire`, `loquere-cli`, schema `loquere://`); "Loquere" solo come nome del prodotto e della cartella dati | §5.2 |
| Encoding di `DeviceCert` | binario canonico versionato e separato per dominio, senza crate di serializzazione | §6.4 (D-20) |
| Parametri Argon2id | 64 MiB, 3 passaggi, parallelismo 1; versionati nell'envelope | §6.1 (D-21) |
| Formato del payload `identity.tck` | payload binario versionato, autenticato con ChaCha20-Poly1305 | §16 (D-22) |
| Protezione account con passphrase | MK casuale avvolta da Argon2id in un envelope esterno versionato | §6.1 (D-23) |
| Payload invito verificabile | include `DeviceCert` completo; firma DK domain-separated e Base32 RFC 4648 | §7.1 (D-24) |
| Framing append-only locale | lunghezza u32 LE + envelope AEAD; sequenza autenticata; limite 16 MiB | §16 (D-25) |
| Prefisso filtro silenzioso | timestamp BE + key ID opaco + MAC BLAKE2s a 16 byte, anti-replay limitato | §8.3 (D-26, D-32) |
| Simulatore | SplitMix64 deterministico per seed, link con latenza/jitter/perdita/banda/partizioni | §22 (D-27) |
| Token Retry QUIC | HKDF-SHA256 domain-separated + ChaCha20-Poly1305; tempo iniettato | §8.3 (D-28) |
| Driver QUIC | `QuicNode` sans-IO sopra `quinn-proto`; ingressi/uscite espliciti, socket al chiamante | §8.3 (D-29) |
| Eventi QUIC | Eventi stream/datagrammi inoltrati all'engine; connessioni perse ripulite | §8.3 (D-30) |
| Metadati UDP | Destinazione, IP sorgente, ECN e segment size preservati attraverso il confine sans-IO | §8.3 (D-31) |
| Gate pre-autenticazione | Token invito/segreto peer + HKDF destinatario; key ID opaco, non chiave pubblica | §8.3 (D-32) |
| Demultiplexing ingresso UDP | Initial identificato dopo il prefisso; altri pacchetti richiedono CID locale autenticato | §8.3 (D-33) |
| Adapter UDP | Socket bloccanti `std`, due famiglie bindate separatamente; metadati non applicabili rifiutati esplicitamente | §9.2 (D-34) |
| Composizione socket e QUIC | `UdpQuicEndpoint` nel thread `net`; clock e scheduling al chiamante | §5.4, §9.2 (D-35) |
| Key ID gate direzionale | La credenziale entrante e quella usata per rispondere sono derivate rispetto al destinatario corretto | §8.3 (D-36) |
| MLS / MSRV | OpenMLS 0.9 e provider 0.6; Rust minimo 1.91 per rispettare MSRV dichiarata | §15.4, §21 (D-37) |
| Persistenza MLS | Ripristino OpenMLS dall'ultimo snapshot autenticato nel log cifrato; compattazione ancora necessaria | §15.4, §16 (D-38) |

### 25.1 Da verificare con i prototipi (M0–M1)

Non sono scelte da fare, ma conferme tecniche che i prototipi devono dare:

- supporto di `rustls` alle chiavi pubbliche grezze (RFC 7250) in entrambi i versi, con verificatore personalizzato;
- `quinn-proto` guidato dal thread `net` senza `tokio`, con Connection ID generati da noi e senza *stateless reset* né *version negotiation* verso l'esterno;
- relay di connessioni QUIC annidate su reti con MTU ridotta (R-16);
- ordinamento dei commit MLS nel simulatore con partizioni (R-11).

---

## Appendice A — Glossario

| Termine | Significato |
|---|---|
| **Account** | l'identità di una persona: la chiave `IK`, che gli amici conoscono come AccountId |
| **Dispositivo / nodo** | un'istanza di Loquere in esecuzione, con chiavi proprie certificate dall'account; Admin se custodisce `IK`, Member altrimenti |
| **MLS** | Messaging Layer Security (RFC 9420): protocollo standard per la cifratura end-to-end di gruppi, con forward secrecy e sicurezza post-compromissione |
| **QUIC** | protocollo di trasporto standard su UDP (quello di HTTP/3): connessioni cifrate con TLS 1.3, stream affidabili e datagrammi non affidabili sulla stessa connessione |
| **Filtro silenzioso** | controllo economico davanti a QUIC, ispirato a WireGuard: chi non conosce la chiave del destinatario viene scartato senza risposta e senza calcoli costosi |
| **Casella postale** | un nodo sempre acceso che custodisce messaggi cifrati per un destinatario offline |
| **NAT** | il meccanismo del router che condivide un IP pubblico tra più dispositivi; impedisce le connessioni in ingresso |
| **CGNAT** | NAT applicato dall'operatore (comune su reti mobili): l'utente non controlla nemmeno il router |
| **Hole punching** | due nodi dietro NAT si inviano pacchetti nello stesso momento per aprire un varco reciproco |
| **Relay** | un terzo nodo che inoltra pacchetti cifrati tra due nodi che non riescono a parlarsi direttamente |
| **Host / SFU** | il nodo che in una chiamata di gruppo riceve i flussi di tutti e li inoltra, senza decifrarli |
| **Simulcast** | lo stesso video inviato in più qualità contemporaneamente, così l'host sceglie quella giusta per ciascuno |
| **Jitter buffer** | piccola attesa in ricezione che assorbe le variazioni di ritardo dei pacchetti |
| **AEC** | cancellazione dell'eco acustica (la tua voce che rientra dal microfono di chi ascolta senza cuffie) |
| **Epoch** | contatore crescente dello stato della chiamata; il piano con epoch più alto vince |
| **Nodo àncora** | un nodo Loquere sempre acceso e raggiungibile che aiuta i propri amici a connettersi |
| **Sans-IO** | stile di programmazione in cui la logica del protocollo non fa I/O direttamente, per essere testabile in modo deterministico |

## Appendice B — Riferimenti

- ArtCraft e Crafting Apps — https://getartcraft.com/apps
- SoundCraft (struttura del workspace, canale di controllo, CLI) — https://github.com/storytold/soundcraft
- RFC 9000 (QUIC), RFC 9221 (datagrammi QUIC), RFC 7250 (chiavi pubbliche grezze in TLS)
- `quinn-proto` — https://docs.rs/quinn-proto
- `rustls` — https://docs.rs/rustls
- WireGuard (modello del filtro silenzioso e dell'anti-replay) — https://www.wireguard.com/papers/wireguard.pdf
- RFC 6716 (Opus), RFC 6887 (PCP), RFC 6886 (NAT-PMP), RFC 9605 (SFrame), RFC 9420 (MLS), RFC 6298 (calcolo RTO)
- OpenMLS — https://openmls.tech
- UnifiedPush — https://unifiedpush.org
- `opus1` — https://docs.rs/crate/opus1/latest
- `sonora` — https://docs.rs/crate/sonora/latest
- `rav1d` — https://www.memorysafety.org/blog/rav1d-perf-bounty/
