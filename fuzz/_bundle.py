# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The bundle `fuzz_scan.py` and `fuzz_forks.py` read a result against.

`seed_scan.identify.identify` wrote it for BIP84's mnemonic, ``abandon``
eleven times and then ``about``, with one account of each purpose and two
keys for a layout held key by key, and these accounts of it are kept:
Bitcoin's of purposes 44 and 84, Ethereum's of purpose 44, its legacy
layout and its layout held key by key, and Bitcoin Cash's. `forks` reads
the first and the last, and lists the second as not checked. Few accounts
keep a run short: both readers check the bundle's keys as they read a
result.

A seed of either corpus names this text by its SHA-256, so a change here
is a change of those seeds.
"""

BUNDLE = """\
{
  "format": "seed-scan-bundle",
  "version": 2,
  "claims": [
    "bip39"
  ],
  "readings": [
    {
      "scheme": "bip39",
      "languages": [
        "en"
      ],
      "passphrase": 0,
      "master_fingerprint": "73c5da0a",
      "accounts": [
        {
          "coin": "bitcoin",
          "coin_type": 0,
          "purpose": 44,
          "account": 0,
          "path": "m/44h/0h/0h",
          "xpub": "xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj",
          "descriptors": [
            "pkh([73c5da0a/44h/0h/0h]xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj/0/*)#5l2aanww",
            "pkh([73c5da0a/44h/0h/0h]xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj/1/*)#9t0uqx7k"
          ],
          "index": null,
          "keys": []
        },
        {
          "coin": "bitcoin",
          "coin_type": 0,
          "purpose": 84,
          "account": 0,
          "path": "m/84h/0h/0h",
          "xpub": "xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V",
          "descriptors": [
            "wpkh([73c5da0a/84h/0h/0h]xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V/0/*)#afwvtk2s",
            "wpkh([73c5da0a/84h/0h/0h]xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V/1/*)#vatdkr6g"
          ],
          "index": null,
          "keys": []
        },
        {
          "coin": "ethereum",
          "coin_type": 60,
          "purpose": 44,
          "account": 0,
          "path": "m/44h/60h/0h",
          "xpub": "xpub6DCoCpSuQZB2jawqnGMEPS63ePKWkwWPH4TU45Q7LPXWuNd8TMtVxRrgjtEshuqpK3mdhaWHPFsBngh5GFZaM6si3yZdUsT8ddYM3PwnATt",
          "descriptors": [],
          "index": null,
          "keys": []
        },
        {
          "coin": "ethereum",
          "coin_type": 60,
          "purpose": null,
          "account": 0,
          "path": "m/44h/60h/0h",
          "xpub": "xpub6DCoCpSuQZB2jawqnGMEPS63ePKWkwWPH4TU45Q7LPXWuNd8TMtVxRrgjtEshuqpK3mdhaWHPFsBngh5GFZaM6si3yZdUsT8ddYM3PwnATt",
          "descriptors": [],
          "index": null,
          "keys": []
        },
        {
          "coin": "ethereum",
          "coin_type": 60,
          "purpose": null,
          "account": 1,
          "path": "m/44h/60h",
          "xpub": "",
          "descriptors": [],
          "index": null,
          "keys": [
            "03d6af9a2aef8cfecd5ceb5606bc606dcde5e484065f9b9855c29ba6906a2d4df4",
            "02413c5a0c131a1463d5e954740c058235da4cb40398d98dcfa1576ae86ee17e7c"
          ]
        },
        {
          "coin": "bitcoin-cash",
          "coin_type": 145,
          "purpose": 44,
          "account": 0,
          "path": "m/44h/145h/0h",
          "xpub": "xpub6ByHsPNSQXTWZ7PLESMY2FufyYWtLXagSUpMQq7Un96SiThZH2iJB1X7pwviH1WtKVeDP6K8d6xxFzzoaFzF3s8BKCZx8oEDdDkNnp4owAZ",
          "descriptors": [],
          "index": null,
          "keys": []
        }
      ]
    }
  ],
  "not_checked": [],
  "search": null
}
"""
