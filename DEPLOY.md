# دليل النشر — بيئة اختبار عامة
## ASA Events Registration · GitHub Pages + Cloudflare Worker + D1 + Resend

الهدف: رابط يعمل يستطيع أي شخص تجربته، مع تخزين فعلي للبيانات وتفعيل رمز التحقق بالبريد.

> **تحذير:** هذه بيئة اختبار تخزّن البيانات خارج مصر. استخدم بيانات مُفتعلة فقط، ولا تُدخل بيانات مشارك حقيقي. راجع المادة 14 من قانون 151 لسنة 2020 واللائحة التنفيذية 816 لسنة 2025.

الوقت المتوقع: ساعة إلى ساعتين، أطولها التحقق من النطاق لدى Resend.

---

## بنية المستودع

```
asa-events-test/
├── robots.txt
├── register/
│   ├── index.html          (registration.html بعد إعادة التسمية)
│   └── registration.js
└── worker/                 (لا يُنشر على Pages، فقط للحفظ والنشر عبر wrangler)
    ├── wrangler.toml
    ├── schema.sql
    └── src/index.js
```

`robots.txt` في الجذر:
```
User-agent: *
Disallow: /
```

---

## الخطوة 1 — الواجهة على GitHub Pages

1. أنشئ مستودعاً عاماً باسم `asa-events-test` على حسابك.
2. ارفع البنية أعلاه.
3. `Settings ← Pages`: المصدر `Deploy from a branch`، الفرع `main`، المجلد `/ (root)`. فعّل `Enforce HTTPS`.
4. الرابط بعد دقيقتين:
   `https://mostafamaarof.github.io/asa-events-test/register/`

**للربط بنطاقك:** أضف سجل CNAME باسم `events` يشير إلى `mostafamaarof.github.io`، ثم اكتب `events.mostafamaarof.com` في `Settings ← Pages ← Custom domain`.

---

## الخطوة 2 — قاعدة البيانات D1

يتطلب Node.js على جهازك.

```bash
cd worker
npx wrangler login
npx wrangler d1 create asa-events
```

انسخ `database_id` الظاهر في المخرجات وضعه في `wrangler.toml` مكان `PUT-YOUR-D1-DATABASE-ID-HERE`. ثم:

```bash
npx wrangler d1 execute asa-events --remote --file=./schema.sql
```

`schema.sql` ينشئ الجداول ويُدخل الحدثين ورمزَي دعوة للتجربة:

| الرمز | الغرض |
|---|---|
| `ASA-WGITA35-TST-4M7K` | دعوة عادية، تتطلب بريد جهة عمل |
| `ASA-DEMO-EXP-9K4T` | دعوة تسمح ببريد شخصي مثل Gmail |

---

## الخطوة 3 — البريد عبر Resend

هذه الخطوة الأطول لأنها تنتظر انتشار سجلات DNS.

1. أنشئ حساباً على resend.com.
2. `Domains ← Add Domain` وأدخل `mostafamaarof.com`.
3. أضف سجلات SPF و DKIM التي يعرضها Resend في لوحة إدارة نطاقك، وانتظر التحقق (من دقائق إلى ساعات).
4. `API Keys ← Create` واحتفظ بالمفتاح.

بدون التحقق من النطاق لن تصل رسائل رمز التحقق إلا إلى بريدك أنت، ولن يستطيع الآخرون التجربة.

عدّل `MAIL_FROM` في `wrangler.toml` ليطابق نطاقك المُتحقق منه.

---

## الخطوة 4 — نشر الخادم

```bash
npx wrangler secret put RESEND_API_KEY     # مفتاح Resend
npx wrangler secret put SESSION_SECRET     # نص عشوائي طويل، مثلاً من: openssl rand -base64 48
npx wrangler secret put ADMIN_TOKEN        # نص عشوائي طويل آخر
npx wrangler deploy
```

يظهر رابط مثل `https://asa-events-api.<account>.workers.dev`. تحقق منه:

```bash
curl https://asa-events-api.<account>.workers.dev/v1/health
```

تأكد أن `ALLOWED_ORIGINS` في `wrangler.toml` يحتوي رابط صفحتك على Pages، وإلا سيرفض المتصفح الطلبات.

---

## الخطوة 5 — ربط الواجهة بالخادم

في مطلع `register/registration.js`:

```js
const CONFIG = {
  apiBase: 'https://asa-events-api.<account>.workers.dev/v1',
  MOCK: false,
  ...
};
```

ارفع التعديل. انتهى: الرابط يعمل بالكامل مع رمز تحقق حقيقي وتخزين فعلي.

---

## الخطوة 6 — قراءة البيانات

لا توجد لوحة إدارة في هذه المرحلة. تقرأ البيانات بمسارين محميين برمز الإدارة:

```bash
curl -H "Authorization: Bearer <ADMIN_TOKEN>" \
  https://asa-events-api.<account>.workers.dev/v1/admin/registrations

curl -H "Authorization: Bearer <ADMIN_TOKEN>" \
  -o registrations.csv \
  https://asa-events-api.<account>.workers.dev/v1/admin/export.csv
```

ملف CSV يفتح في Excel مباشرة بترميز عربي سليم.

أو استعلم من قاعدة البيانات:
```bash
npx wrangler d1 execute asa-events --remote \
  --command "SELECT reference, full_name, organization_name, status FROM registrations ORDER BY created_at DESC"
```

---

## كيف تُخزَّن البيانات

**جدول `registrations`.** الحقول التي يُستعلَم عنها كثيراً مستخرجة في أعمدة مستقلة: المرجع، الحالة، الاسم، البريد، الجهة، الدولة، نمط الحضور، الصفة، حاجة التأشيرة. وباقي الاستمارة كاملة في عمود `data_json`.

سبب هذا التصميم أن الاستمارة تتغير: تضيف حقلاً أو تحذف آخر لكل فعالية. لو كان لكل حقل عمود لاحتاج كل تعديل هجرة لقاعدة البيانات. أما هكذا فالحقول الجديدة تدخل `data_json` بلا أي تغيير في الجداول، وتبقى الأعمدة المستخرجة ثابتة للفهرسة والتقارير.

**فهرس فريد على `(event_code, email)`** يمنع التسجيل المكرر على مستوى قاعدة البيانات، لا على مستوى الكود فقط.

**جدول `otps`** يخزّن تجزئة الرمز لا الرمز نفسه، مع وقت انتهاء وعدّاد محاولات، ويُحذف السطر فور التحقق الناجح.

**جدول `audit_log`** يسجل كل إرسال رمز وكل تحقق وكل تسجيل وكل محاولة فاشلة برمز دعوة، مع تجزئة عنوان IP لا العنوان نفسه.

**جدول `throttle`** يطبّق حدود المعدل: عشر محاولات تحقق من الدعوة في الساعة لكل عنوان، وعشرون محاولة رمز، وعشرة تسجيلات.

---

## كيف يعمل رمز التحقق

1. الواجهة ترسل رمز الدعوة والبريد.
2. الخادم يتحقق من الحدث والدعوة والصلاحية وسياسة البريد الشخصي.
3. يولّد ستة أرقام عشوائياً، ويخزّن `SHA-256` لها مضافاً إليها المفتاح السري، وينشئ صلاحية عشر دقائق.
4. يرسل الرمز عبر Resend برسالة ثنائية اللغة.
5. عند التحقق يقارن التجزئة، ويزيد عدّاد المحاولات عند الفشل، ويرفض بعد خمس محاولات.
6. عند النجاح يحذف السطر ويصدر رمز جلسة موقّعاً بـ HMAC صلاحيته ساعتان.
7. كل طلب لاحق يحمل رمز الجلسة في ترويسة `Authorization`.

الرمز الأصلي لا يُخزَّن في أي مكان، فحتى من يقرأ قاعدة البيانات لا يستطيع استخراجه.

---

## ما لم يُنفَّذ في هذه المرحلة

رفع المرفقات إلى R2، فالملفات تبقى على جهاز المستخدم ولا يُرسل إلا وصفها. ولوحة الأمانة ومسار الاعتماد وإصدار رقم التسجيل والـ QR وخطابات التأشيرة والتقارير. جميعها المرحلة الثانية.

لاحظ أن `registration_closes_at` للحدثين مضبوط على نهاية 2026 في `schema.sql` كي تظل التجربة مفتوحة. اضبطه على التاريخ الحقيقي قبل أي استخدام فعلي.
