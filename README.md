# CipherVeil
**"Lock what matters. Hide what's precious."**

একটা Android APK Protection টুল — DEX obfuscation, resource encryption,
anti-tampering, anti-debugging, auto re-signing সহ ২০+ প্রোটেকশন ফিচার।
Stack: **Java + XML (UI)**, **C++/JNI (native hardening)**, **Python (protection engine)**, **GitHub Actions (CI build)**।

---

## আর্কিটেকচার — কেন এভাবে ভাগ করা হলো

একটা ফোন থেকে ১ GB পর্যন্ত APK decompile + re-encrypt + re-sign করা
মেমরি-ইনটেনসিভ কাজ। তাই কাজটা দুই ভাগে ভাগ করা হয়েছে, যাতে অ্যাপটা
বাস্তবে কাজ করে — শুধু দেখতে সুন্দর না:

| স্তর | কী করে | কোথায় চলে |
|---|---|---|
| **Android App** (Java/XML + C++/JNI) | APK সিলেক্ট, স্ট্রিমিং কপি (RAM এ পুরো ফাইল লোড হয় না), নেটিভ ফিঙ্গারপ্রিন্টিং, ফিচার ম্যাট্রিক্স UI, job manifest তৈরি | ফোনেই |
| **Protection Engine** (`tools/protector.py`) | আসল obfuscation, AES-256 এনক্রিপশন, manifest hardening, zipalign + apksigner দিয়ে re-sign | Termux (ফোনেই) / ডেস্কটপ / GitHub Actions |

Android app থেকে বানানো `protection_job.json` ফাইলটাই Python ইঞ্জিনকে
বলে দেয় কোন কোন ফিচার on করা ছিল।

---

## ২৪টা প্রোটেকশন ফিচার

1. DEX Code Obfuscation (ক্লাস/মেথড/ফিল্ড রিনেম, শুধু নিজের প্যাকেজে)
2. AES-256 String Encryption
3. Resource & Asset Encryption
4. Runtime Signature Verification
5. Anti-Debugging Detection (native, TracerPid check)
6. Root Detection Shield
7. Emulator Detection (native heuristic)
8. Native (JNI/C++) Hardening
9. Auto Re-signing (v1/v2/v3)
10. Zipalign Optimization
11. Custom DEX ClassLoader Packing
12. Anti-Repackaging Certificate Lock
13. Frida / Xposed Hook Detection
14. ProGuard + R8 Integration
15. Control-Flow Obfuscation
16. Manifest Hardening
17. SSL Certificate Pinning Injector
18. Protection Watermark / Fingerprint
19. Batch APK Queue Processing
20. Live Protection Report Log
21. Resource Shrink & Size Optimizer
22. Streamed Large-File Handling (1 GB+, OOM-safe)
23. Local Protection History
24. One-Tap Verify Protected APK

---

## কীভাবে GitHub Actions দিয়ে বিল্ড করবে

1. এই পুরো ফোল্ডার একটা নতুন GitHub repo তে পুশ করো
2. `Actions` ট্যাবে যাও → **"CipherVeil CI Build"** workflow রান হবে (push এ auto)
3. বিল্ড শেষে **Artifacts** সেকশন থেকে `CipherVeil-debug-apk` ডাউনলোড করো — এটাই তোমার app এর APK

```
git init
git add .
git commit -m "CipherVeil v1"
git branch -M main
git remote add origin https://github.com/<তোমার-username>/CipherVeil.git
git push -u origin main
```

---

## Python প্রোটেকশন ইঞ্জিন চালানো (Termux এ)

```bash
pkg install python openjdk-17
pip install -r tools/requirements.txt
python tools/protector.py --job protection_job.json --out protected.apk
```

অথবা সরাসরি যেকোনো APK দিয়ে টেস্ট করতে:
```bash
python tools/protector.py --apk target.apk --out protected.apk --all
```

`zipalign` আর `apksigner` লাগবে — এগুলো Android SDK build-tools এ আসে
(`--build-tools` ফ্ল্যাগ দিয়ে পাথ দাও, নাহলে keystore ছাড়া unsigned APK বের হবে)।

---

## সততার সাথে সীমাবদ্ধতা (Honest Limitations)

এই প্রজেক্টটা একটা **real, working architecture**, কিন্তু প্রোডাকশন-গ্রেড
টুল (DexGuard-এর মতো) বানাতে এখনো যা বাকি, সেটা স্বচ্ছভাবে বলে রাখা ভালো:

- `AndroidManifest.xml` বাইনারি AXML ফরম্যাটে থাকে — পুরোপুরি safe edit
  করতে AXML-aware rewriting লাগবে (androguard-এর ARSCParser পাথ ব্যবহার করে
  সম্প্রসারণযোগ্য, `protector.py` তে TODO হিসেবে চিহ্নিত আছে)
- DEX বাইটকোড রিনেমিং করার পর bytecode-level patch (শুধু ম্যাপিং বানানো না,
  বাস্তবে সব reference rewrite করা) আরও টেস্টিং দাবি করে — ভুল হলে app crash
  করতে পারে, তাই প্রোডাকশনে ছাড়ার আগে **সবসময় protected APK টা ইনস্টল করে
  টেস্ট করো**
- Native anti-debug/anti-emulator checks basic-level heuristic — এগুলো
  determined reverse engineer কে আটকায় না, বরং casual tampering/script kiddie
  লেভেলের প্রোটেকশন দেয়

---

## ফোল্ডার স্ট্রাকচার

```
CipherVeil/
├── app/
│   ├── build.gradle
│   └── src/main/
│       ├── AndroidManifest.xml
│       ├── java/com/cipherveil/protector/
│       │   ├── MainActivity.java
│       │   ├── ProtectionEngine.java
│       │   ├── NativeGuard.java
│       │   └── ui/FeatureAdapter.java
│       ├── cpp/
│       │   ├── native-lib.cpp
│       │   └── CMakeLists.txt
│       └── res/   (layouts, cyberpunk colors, animations, adaptive icon)
├── tools/
│   ├── protector.py
│   └── requirements.txt
├── .github/workflows/build.yml
└── README.md
```
