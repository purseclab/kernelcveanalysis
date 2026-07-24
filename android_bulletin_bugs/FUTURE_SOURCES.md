# Future Security-Bulletin Sources

This project currently scrapes the Android Security Bulletin. The following
bulletin families are candidates for expansion, ordered by expected value and
implementation effort.

## First priority: Google bulletin family

These sources are published on AOSP, maintain indexed archives, and use
Android-style CVE tables. They should be implemented with a configurable
source/category layer rather than separate scraper designs.

| Source | URL | Notes |
| --- | --- | --- |
| Pixel Update Bulletins | <https://source.android.com/docs/security/bulletin/pixel> | Monthly; closest extension of the existing parser. |
| Android Automotive OS Update Bulletins | <https://source.android.com/docs/security/bulletin/aaos> | Monthly supplemental CVEs for AAOS. |
| Wear OS Security Bulletins | <https://source.android.com/docs/security/bulletin/wear> | Monthly archive and Android-style vulnerability tables. |
| Android XR Security Bulletins | <https://source.android.com/docs/security/bulletin/xr> | Monthly Android XR bulletins. |
| Pixel Watch Security Bulletins | <https://source.android.com/docs/security/bulletin/pixel-watch> | Similar source, but releases are less regular. |
| Chromecast Security Bulletins | <https://source.android.com/docs/security/bulletin/chromecast> | Official archive, but only periodic releases. |

The [AOSP security-bulletin index](https://source.android.com/docs/security/bulletin)
lists these families and their available editions.

## Second priority: OEM and chipset vendors

These sources add vendor-specific fixes and proprietary-component coverage that
is not fully represented by the Android Security Bulletin.

| Source | URL | Notes |
| --- | --- | --- |
| Samsung Mobile Security Updates | <https://security.samsungmobile.com/securityUpdate.smsb> | Monthly SMR history; includes upstream Android CVEs plus Samsung-specific SVE records and descriptions. |
| Qualcomm Product Security Bulletins | <https://docs.qualcomm.com/product/publicresources/securitybulletin/> | Regular chipset bulletins; useful for proprietary device-specific component CVEs. |
| MediaTek Product Security Bulletins | <https://corp.mediatek.com/product-security-bulletin/December-2025> | Monthly, per-chipset CVE lists grouped by severity. URLs follow a `Month-YYYY` form. |
| UNISOC Security Bulletins | <https://www.unisoc.com/en/support/announcement> | Dated bulletin archive; useful for UNISOC/Spreadtrum Android-device coverage. |

## Third priority: OEM sources requiring source-specific work

| Source | URL | Notes |
| --- | --- | --- |
| OPPO Android Security Advisories | <https://security.oppo.com/en/mend> | Monthly patch advisories, but the site is JavaScript-driven. |
| vivo Security Patch Updates | <https://www.vivo.com/en/security> | Monthly patch/CVE coverage and device-support metadata. |
| OnePlus Security Response Center | <https://security.oneplus.com/en/home> | Likely requires discovering and consuming a JavaScript/API data source. |
| LG Mobile Bulletins | <https://lgsecurity.lge.com/bulletins/mobile> | Official archive, but JavaScript-only. |
| Motorola Security Updates | <https://en-us.support.motorola.com/app/software-security-update/g_id/7112> | Better for per-device update/support status than a clean monthly CVE bulletin. |
| Nokia/HMD | Historical Nokia links now redirect, so this needs separate HMD source discovery. |

Google's [Android Security Bulletin overview](https://source.android.com/docs/security/bulletin/asb-overview?hl=en)
also identifies Samsung, LG, Motorola, Nokia, OnePlus, OPPO, and vivo as
device-manufacturer sources.

## Recommended implementation order

1. Google bulletin families
2. Samsung
3. Qualcomm, MediaTek, and UNISOC
4. OPPO, vivo, OnePlus, and LG
5. Motorola and HMD/Nokia device-support sources

## Data-model changes needed

The existing database makes `cve` globally unique. That would overwrite the
Android record when the same CVE appears in a Samsung, Qualcomm, or other
bulletin. Use a source-aware identity such as
`(source, bulletin, advisory_id_or_cve)` instead, and allow `cve` to be
nullable because vendors may publish their own advisory IDs (for example,
Samsung `SVE-*` entries).

Useful generic fields include: `source`, `bulletin_family`, `bulletin_date`,
`advisory_id`, `cve`, `severity`, `category`, `component`,
`affected_versions`, `reference_url`, `external_reference`, `summary`, and
`disclosure_status`.
