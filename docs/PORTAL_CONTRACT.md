# Протокол портала v3bl.goszakup.gov.kz (сверено по HAR, 27.09.2026)

Источник — запись реальной подачи заявки поставщиком (Chrome DevTools, HAR
sanitized). Секреты (Cookie, csrf, `hsm_api_key`, подписи, код SSO) в документ
не переносятся. Идентификаторы ниже — пример: объявление `17666784`, заявка
`73161291`.

## Общее

* Кабинет — серверный HTML (не JSON-API). Действия — `POST` формы
  `application/x-www-form-urlencoded` с заголовком `X-Requested-With:
  XMLHttpRequest`; ответ — JSON.
* CSRF: поле формы `csrf`. Значение — `<meta name="csrf-token-hash">` или
  `<input id="csrf">` на любой странице кабинета.
* Признак сессии: в шапке каждой страницы вошедшего пользователя есть ссылка
  `/ru/user/sso_logout` («Выход»). Подтверждённые GET-страницы:
  `/ru/cabinet/permits`, `/ru/cabinet/fin_statement`, `/ru/cabinet/tax_debts`,
  `/ru/org_profile/ows_token`.
* Вход: `zakup.gov.kz` SSO. NCALayer `kz.gov.pki.knca.commonUtils.signXml`
  (`PKCS12`, ключ `AUTH`, `<root></root>`) → `POST /api/sso/signature/validate/`
  → `POST /api/sso/internal/authorize` → `GET /api/sso/connect/authorize` →
  `/sso/callback?code=…`. Сессия v3bl — Cookie после `/ru/user/sso_redirect`.

## Локальные программы

| Программа | Адрес | Для чего |
|---|---|---|
| NCALayer | `wss://127.0.0.1:13579/` | подпись: модуль `NURSign` (`{"module":"NURSign","type":"multitext","data":{id: text},"source":"local"}` → `result.items[id]` = CMS base64) |
| TumarCSP (криптосокет ЦЭФ) | `wss://127.0.0.1:6127/tumarcsp/` (резерв `ws://127.0.0.1:6126/tumarcsp/`) | шифрование ценового предложения |

TumarCSP: `SYSAPI.SetAPIKey` (`apiKey` = `hsm_api_key` из inline-скрипта
страницы) → `BaseAPI.GetVersion {type: 3}` → `EFCAPI.EncryptOfferPrice`.
В `EncryptOfferPrice` передаются только плановая и демпинговая суммы,
`id_priceoffer`, `public_key` (скрытое поле страницы), `salt`, `sign` —
**саму цену вводит пользователь в окне TumarCSP**; портал получает только
шифртекст (`encryptData`, `encryptKey`, `sn`, `sign`).

## Шаги заявки (записаны начиная с ценовых предложений)

Шаги до ценовых предложений (создание заявки, выбор лотов, документы,
квалификация) в записи **отсутствуют**.

1. `GET /ru/application/priceoffers/{anno}/{app}`
2. Для каждого пункта (лота) `lpId`:
   * `POST /ru/application/ajax_get_encr_info/{anno}/{app}` — `lpId`, `version`
     (TumarCSP), `csrf` → `{status:1, plnSum, minPrice, salt, info, sign}`;
   * TumarCSP `EncryptOfferPrice` (ввод цены пользователем);
   * `POST /ru/application/ajax_add_encrypt/{anno}/{app}` — `itemID`,
     `encryptedData`, `sessionKey`, `salt`, `info` (= `sn`), `sign`, `csrf` →
     `{status:1}`.
3. «Подписать цены»: NCALayer `NURSign multitext` по шифртекстам →
   `POST /ru/application/ajax_save_gamma_signs/{anno}/{app}` —
   `xmlData[lpId]`, `signData[lpId]` (CMS), `csrf` → `{status:0}` (0 = успех).
4. `POST /ru/application/ajax_priceoffers_next/{anno}/{app}` —
   `offer[{lotId}][{lpId}][price]` = шифртекст, `is_construction_pilot`, `csrf`
   → `{status:1}`; далее `GET /ru/application/preview/{anno}/{app}`.
5. **Подача**: `POST /ru/application/ajax_public_application/{anno}/{app}` —
   `public_app=Y`, `agree_price`, `agree_contract_project`, `agree_covid19`
   (`true`/`false`), `csrf`. Успех: `{"status":"ok","debtor":0}` → переход на
   `/ru/myapp/actionShowApp/{app}`. Ошибка: `{"status":"error","debtor":0|1,
   "message":"…"}`. Время ответа сервера 1.3–1.8 с.
   * JS страницы добавляет `recaptcha` (`g-recaptcha-response`), если загружен
     reCAPTCHA; скрипт reCAPTCHA на странице предпросмотра есть, но в
     записанной успешной подаче поле не отправлялось.

## Предусловие подачи: сведения о налоговой задолженности

Без сведений, полученных **не раньше даты публикации объявления**, подача
возвращает `status:error` («необходимо иметь актуальные запрошенные сведения о
налоговой задолженности…»). Запрос: `POST /ru/cabinet/tax_debts` — `csrf`,
`send_request` → `302` на ту же страницу; ответ ИС приходит не сразу.

## Расхождения с текущим кодом

* `PortalEndpoints.bid_*` (`/api/bid/...`), `auth_*`, `session_ping_path` — не
  существуют; реальные действия — `ajax_*` выше.
* `NCALayerClient` работает с `kz.gov.pki.knca.basics`; портал подписывает
  через `NURSign` (`multitext`/`binary`).
* Шифрование цены через TumarCSP в конвейере отсутствует.

Реализовано по этому протоколу: `core/draft_submit.py` (подача черновика в T0,
налоговые сведения, проверка капчи) и keep-alive сессии страницей кабинета.
**LIVE-подача подготовленной заявки разрешена** — контракт подтверждён
константой `CABINET_PAGES_CONTRACT_VERIFIED` в `config/settings.py` (менять
только там). Старый конвейер (`core/bid_pipeline.py`, `/api/bid/...`) в LIVE
по-прежнему заблокирован: этих путей на портале не существует.
