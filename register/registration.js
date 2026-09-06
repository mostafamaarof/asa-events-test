/* =============================================================================
   ASA Events — Unified Registration Form (frontend)
   Spec: ASA-Events-Unified-Registration-Form-Spec-v1.0
   Static build. Deployable to GitHub Pages. All privileged logic lives in the API.
   ============================================================================= */

/* ---------------------------------------------------------------------------
   1. CONFIGURATION
   Set MOCK=false and apiBase to the deployed Worker once the backend is live.
   --------------------------------------------------------------------------- */
const CONFIG = {
  apiBase: 'https://asa-events-api.mostafamaarof.workers.dev/v1',
  MOCK: false,                      // demo mode: no network calls
  turnstileSiteKey: '',             // fill in to enable Cloudflare Turnstile
  draftKey: 'asa_reg_draft_v1',
  minFillSeconds: 15,               // bot heuristic, enforced again server-side
  mockFreeEmailCodes: ['ASA-DEMO-EXP-9K4T'],  // demo only; live this comes from invitations.allow_free_email
  supportEmail: 'events@mostafamaarof.com'
};

/* Event registry. Add an entry per event; nothing else needs to change. */
const EVENTS = {
  'WGITA-35-2026': {
    code: 'WGITA-35-2026',
    title: { en: '35th WGITA Annual Meeting', ar: 'الاجتماع السنوي الخامس والثلاثون لفريق العمل المعني بتدقيق تكنولوجيا المعلومات' },
    short: { en: 'WGITA 2026', ar: 'WGITA 2026' },
    dates: { en: '27–29 September 2026', ar: '27 – 29 سبتمبر 2026' },
    startDate: '2026-09-27', endDate: '2026-09-29',
    venue: { en: 'Cairo, Arab Republic of Egypt', ar: 'القاهرة، جمهورية مصر العربية' },
    hybrid: true,
    closesAt: '2026-09-21T23:59:00+02:00',
    hotels: ['Al Masa Hotel, Nasr City', 'Triumph Luxury Hotel, Heliopolis', 'Hilton Cairo Heliopolis']
  },
  'KSC-SC18-2026': {
    code: 'KSC-SC18-2026',
    title: { en: '18th Meeting of the KSC Steering Committee', ar: 'الاجتماع الثامن عشر للجنة التوجيهية للجنة تبادل المعرفة' },
    short: { en: 'KSC SC 2026', ar: 'KSC SC 2026' },
    dates: { en: '30 September 2026', ar: '30 سبتمبر 2026' },
    startDate: '2026-09-30', endDate: '2026-09-30',
    venue: { en: 'Cairo, Arab Republic of Egypt', ar: 'القاهرة، جمهورية مصر العربية' },
    hybrid: true,
    closesAt: '2026-09-21T23:59:00+02:00',
    hotels: ['Al Masa Hotel, Nasr City', 'Triumph Luxury Hotel, Heliopolis', 'Hilton Cairo Heliopolis']
  }
};

/* Never written to the device draft. */
const SENSITIVE = new Set([
  'passport_number', 'medical_notes_emergency', 'allergies',
  'emergency_contact_phone', 'acc_passport_number'
]);

/* ---------------------------------------------------------------------------
   2. INTERFACE STRINGS
   --------------------------------------------------------------------------- */
const UI = {
  sections:      { en: 'Sections', ar: 'الأقسام' },
  step:          { en: 'Step', ar: 'خطوة' },
  of:            { en: 'of', ar: 'من' },
  back:          { en: 'Back', ar: 'رجوع' },
  next:          { en: 'Continue', ar: 'متابعة' },
  submit:        { en: 'Submit registration', ar: 'إرسال التسجيل' },
  saveExit:      { en: 'Save and exit', ar: 'حفظ وخروج' },
  draftSaved:    { en: 'Draft saved on this device', ar: 'حُفظت المسودة على هذا الجهاز' },
  draftOff:      { en: 'Draft saving unavailable in this browser', ar: 'حفظ المسودة غير متاح في هذا المتصفح' },
  required:      { en: 'required', ar: 'مطلوب' },
  optional:      { en: 'Optional', ar: 'اختياري' },
  chooseFile:    { en: 'Choose file', ar: 'اختر ملفاً' },
  remove:        { en: 'Remove', ar: 'إزالة' },
  noFile:        { en: 'No file selected', ar: 'لم يتم اختيار ملف' },
  edit:          { en: 'Edit', ar: 'تعديل' },
  yes:           { en: 'Yes', ar: 'نعم' },
  no:            { en: 'No', ar: 'لا' },
  select:        { en: 'Select…', ar: 'اختر…' },
  add:           { en: 'Add', ar: 'إضافة' },
  notProvided:   { en: 'Not provided', ar: 'غير مُدخل' },
  errFix:        { en: 'Check the highlighted fields before continuing.', ar: 'راجع الحقول المميزة قبل المتابعة.' },
  errRequired:   { en: 'This field is required.', ar: 'هذا الحقل مطلوب.' },
  errEmail:      { en: 'Enter a valid email address.', ar: 'أدخل بريداً إلكترونياً صحيحاً.' },
  errFreeEmail:  { en: 'This invitation requires an institutional email. Write to the secretariat if you do not have one.', ar: 'هذه الدعوة تتطلب بريد جهة العمل. راسل الأمانة إذا لم يكن لديك بريد مؤسسي.' },
  errDisposable: { en: 'Temporary and disposable addresses are not accepted.', ar: 'لا تُقبل العناوين المؤقتة أو المُستهلكة.' },
  errPhone:      { en: 'Include the country code, for example +20 100 000 0000.', ar: 'أدرج رمز الدولة، مثال ‎+20 100 000 0000.' },
  errCode:       { en: 'Invalid or expired invitation code.', ar: 'رمز الدعوة غير صحيح أو منتهي الصلاحية.' },
  errOtp:        { en: 'That code did not match. Check your inbox and try again.', ar: 'الرمز غير مطابق. راجع بريدك وحاول مجدداً.' },
  errMinLen:     { en: 'Too short.', ar: 'النص قصير جداً.' },
  errMaxLen:     { en: 'Too long.', ar: 'النص طويل جداً.' },
  errDate:       { en: 'Check this date.', ar: 'راجع هذا التاريخ.' },
  errFileType:   { en: 'Allowed formats: PDF, JPG, PNG.', ar: 'الصيغ المسموحة: PDF أو JPG أو PNG.' },
  errFileSize:   { en: 'File exceeds the size limit.', ar: 'حجم الملف يتجاوز الحد المسموح.' },
  errAge:        { en: 'Registrant must be 18 or older.', ar: 'يجب ألا يقل العمر عن 18 عاماً.' },
  errCheckout:   { en: 'Check-out must be after check-in.', ar: 'تاريخ المغادرة يجب أن يلي تاريخ الوصول.' },
  warnPassport:  { en: 'This passport expires less than six months after the meeting ends. Many entry regimes require six months of validity. You can continue, but please verify with the Egyptian mission.', ar: 'ينتهي هذا الجواز قبل ستة أشهر من انتهاء الاجتماع. تشترط معظم أنظمة الدخول صلاحية ستة أشهر. يمكنك المتابعة، لكن يُرجى المراجعة مع البعثة المصرية.' },
  closed:        { en: 'Registration is closed', ar: 'التسجيل مغلق' },
  closedBody:    { en: 'The registration period for this meeting has ended. Write to the secretariat if you believe this is an error.', ar: 'انتهت فترة التسجيل لهذا الاجتماع. راسل الأمانة إذا كنت ترى أن هناك خطأ.' },
  reviewTitle:   { en: 'Review and submit', ar: 'المراجعة والإرسال' },
  reviewDesc:    { en: 'Check every section once. You can still edit anything before submitting.', ar: 'راجع كل قسم مرة أخيرة. يمكنك تعديل أي بيان قبل الإرسال.' },
  sending:       { en: 'Sending…', ar: 'جارٍ الإرسال…' },
  netErr:        { en: 'The request could not be completed. Check your connection and try again.', ar: 'تعذّر إتمام الطلب. تحقق من الاتصال وحاول مجدداً.' },
  errExpired:    { en: 'Your session has expired. Reload the page and verify your email again — your draft is kept.', ar: 'انتهت صلاحية الجلسة. أعد تحميل الصفحة وتحقق من بريدك مجدداً، ومسودتك محفوظة.' },
  errDuplicate:  { en: 'A registration already exists for this email. Contact the secretariat to amend it.', ar: 'يوجد تسجيل بهذا البريد بالفعل. راسل الأمانة لتعديله.' }
};

const T = (k) => (UI[k] ? UI[k][state.lang] : k);
const L = (o) => (o && typeof o === 'object' ? (o[state.lang] ?? o.en) : o);

/* ---------------------------------------------------------------------------
   3. OPTION SETS
   Country names stay in English in both locales: they must match travel documents.
   --------------------------------------------------------------------------- */
const COUNTRIES_RAW = "AF:Afghanistan|AL:Albania|DZ:Algeria|AS:American Samoa|AD:Andorra|AO:Angola|AI:Anguilla|AQ:Antarctica|AG:Antigua and Barbuda|AR:Argentina|AM:Armenia|AW:Aruba|AU:Australia|AT:Austria|AZ:Azerbaijan|BS:Bahamas|BH:Bahrain|BD:Bangladesh|BB:Barbados|BY:Belarus|BE:Belgium|BZ:Belize|BJ:Benin|BM:Bermuda|BT:Bhutan|BO:Bolivia|BQ:Bonaire, Sint Eustatius and Saba|BA:Bosnia and Herzegovina|BW:Botswana|BV:Bouvet Island|BR:Brazil|IO:British Indian Ocean Territory|BN:Brunei Darussalam|BG:Bulgaria|BF:Burkina Faso|BI:Burundi|CV:Cabo Verde|KH:Cambodia|CM:Cameroon|CA:Canada|KY:Cayman Islands|CF:Central African Republic|TD:Chad|CL:Chile|CN:China|CX:Christmas Island|CC:Cocos (Keeling) Islands|CO:Colombia|KM:Comoros|CG:Congo|CD:Congo, The Democratic Republic of the|CK:Cook Islands|CR:Costa Rica|HR:Croatia|CU:Cuba|CW:Curaçao|CY:Cyprus|CZ:Czechia|CI:Côte d'Ivoire|DK:Denmark|DJ:Djibouti|DM:Dominica|DO:Dominican Republic|EC:Ecuador|EG:Egypt|SV:El Salvador|GQ:Equatorial Guinea|ER:Eritrea|EE:Estonia|SZ:Eswatini|ET:Ethiopia|FK:Falkland Islands (Malvinas)|FO:Faroe Islands|FJ:Fiji|FI:Finland|FR:France|GF:French Guiana|PF:French Polynesia|TF:French Southern Territories|GA:Gabon|GM:Gambia|GE:Georgia|DE:Germany|GH:Ghana|GI:Gibraltar|GR:Greece|GL:Greenland|GD:Grenada|GP:Guadeloupe|GU:Guam|GT:Guatemala|GG:Guernsey|GN:Guinea|GW:Guinea-Bissau|GY:Guyana|HT:Haiti|HM:Heard Island and McDonald Islands|VA:Holy See (Vatican City State)|HN:Honduras|HK:Hong Kong|HU:Hungary|IS:Iceland|IN:India|ID:Indonesia|IR:Iran|IQ:Iraq|IE:Ireland|IM:Isle of Man|IL:Israel|IT:Italy|JM:Jamaica|JP:Japan|JE:Jersey|JO:Jordan|KZ:Kazakhstan|KE:Kenya|KI:Kiribati|KP:North Korea|KR:South Korea|KW:Kuwait|KG:Kyrgyzstan|LA:Laos|LV:Latvia|LB:Lebanon|LS:Lesotho|LR:Liberia|LY:Libya|LI:Liechtenstein|LT:Lithuania|LU:Luxembourg|MO:Macao|MG:Madagascar|MW:Malawi|MY:Malaysia|MV:Maldives|ML:Mali|MT:Malta|MH:Marshall Islands|MQ:Martinique|MR:Mauritania|MU:Mauritius|YT:Mayotte|MX:Mexico|FM:Micronesia, Federated States of|MD:Moldova|MC:Monaco|MN:Mongolia|ME:Montenegro|MS:Montserrat|MA:Morocco|MZ:Mozambique|MM:Myanmar|NA:Namibia|NR:Nauru|NP:Nepal|NL:Netherlands|NC:New Caledonia|NZ:New Zealand|NI:Nicaragua|NE:Niger|NG:Nigeria|NU:Niue|NF:Norfolk Island|MK:North Macedonia|MP:Northern Mariana Islands|NO:Norway|OM:Oman|PK:Pakistan|PW:Palau|PS:Palestine, State of|PA:Panama|PG:Papua New Guinea|PY:Paraguay|PE:Peru|PH:Philippines|PN:Pitcairn|PL:Poland|PT:Portugal|PR:Puerto Rico|QA:Qatar|RO:Romania|RU:Russian Federation|RW:Rwanda|RE:Réunion|BL:Saint Barthélemy|SH:Saint Helena, Ascension and Tristan da Cunha|KN:Saint Kitts and Nevis|LC:Saint Lucia|MF:Saint Martin (French part)|PM:Saint Pierre and Miquelon|VC:Saint Vincent and the Grenadines|WS:Samoa|SM:San Marino|ST:Sao Tome and Principe|SA:Saudi Arabia|SN:Senegal|RS:Serbia|SC:Seychelles|SL:Sierra Leone|SG:Singapore|SX:Sint Maarten (Dutch part)|SK:Slovakia|SI:Slovenia|SB:Solomon Islands|SO:Somalia|ZA:South Africa|GS:South Georgia and the South Sandwich Islands|SS:South Sudan|ES:Spain|LK:Sri Lanka|SD:Sudan|SR:Suriname|SJ:Svalbard and Jan Mayen|SE:Sweden|CH:Switzerland|SY:Syria|TW:Taiwan|TJ:Tajikistan|TZ:Tanzania|TH:Thailand|TL:Timor-Leste|TG:Togo|TK:Tokelau|TO:Tonga|TT:Trinidad and Tobago|TN:Tunisia|TM:Turkmenistan|TC:Turks and Caicos Islands|TV:Tuvalu|TR:Türkiye|UG:Uganda|UA:Ukraine|AE:United Arab Emirates|GB:United Kingdom|US:United States|UM:United States Minor Outlying Islands|UY:Uruguay|UZ:Uzbekistan|VU:Vanuatu|VE:Venezuela|VN:Vietnam|VG:Virgin Islands, British|VI:Virgin Islands, U.S.|WF:Wallis and Futuna|EH:Western Sahara|YE:Yemen|ZM:Zambia|ZW:Zimbabwe|AX:Åland Islands";
const COUNTRIES = COUNTRIES_RAW.split('|').map(s => {
  const i = s.indexOf(':');
  return { v: s.slice(0, i), l: { en: s.slice(i + 1), ar: s.slice(i + 1) } };
});

const O = (arr) => arr.map(([v, en, ar]) => ({ v, l: { en, ar } }));

const OPT = {
  salutation: O([
    ['HE', 'H.E.', 'سعادة'], ['Hon', 'Hon.', 'الأونرابل'], ['Amb', 'Amb.', 'السفير'],
    ['Prof', 'Prof.', 'أ.د.'], ['Dr', 'Dr', 'د.'], ['Eng', 'Eng.', 'م.'],
    ['Mr', 'Mr', 'السيد'], ['Ms', 'Ms', 'السيدة']
  ]),
  gender: O([['female', 'Female', 'أنثى'], ['male', 'Male', 'ذكر'], ['na', 'Prefer not to say', 'أفضل عدم الإفصاح']]),
  corrLang: O([['en', 'English', 'English'], ['ar', 'العربية', 'العربية'], ['fr', 'Français', 'Français']]),
  orgType: O([
    ['sai', 'INTOSAI member SAI', 'جهاز رقابة عضو بالإنتوساي'],
    ['regional', 'Regional organisation secretariat', 'أمانة منظمة إقليمية'],
    ['body', 'INTOSAI working group, committee or task force', 'فريق عمل أو لجنة بالإنتوساي'],
    ['partner', 'Donor or partner organisation', 'جهة مانحة أو شريكة'],
    ['un', 'UN or international organisation', 'منظمة أممية أو دولية'],
    ['academia', 'Academia', 'جهة أكاديمية'],
    ['private', 'Private sector', 'قطاع خاص'],
    ['expert', 'Invited expert', 'خبير مدعو'],
    ['asa', 'Accountability State Authority', 'الجهاز المركزي للمحاسبات']
  ]),
  region: O([
    ['ARABOSAI', 'ARABOSAI', 'الأرابوساي'], ['AFROSAI', 'AFROSAI', 'الأفروساي'],
    ['AFROSAI-E', 'AFROSAI-E', 'الأفروساي-إي'], ['ASOSAI', 'ASOSAI', 'الآسوساي'],
    ['CAROSAI', 'CAROSAI', 'الكاروساي'], ['EUROSAI', 'EUROSAI', 'اليوروساي'],
    ['OLACEFS', 'OLACEFS', 'الأولاسيفس'], ['PASAI', 'PASAI', 'الباساي'],
    ['na', 'Not applicable', 'لا ينطبق']
  ]),
  protocol: O([
    ['head', 'Head of SAI', 'رئيس جهاز رقابي'],
    ['deputy', 'Deputy or Vice-President', 'نائب الرئيس'],
    ['ag', 'Auditor General', 'المراقب العام'],
    ['dg', 'Director General', 'مدير عام'],
    ['director', 'Director', 'مدير'],
    ['manager', 'Manager or head of unit', 'رئيس قسم'],
    ['expert', 'Auditor or expert', 'مراقب أو خبير'],
    ['other', 'Other', 'أخرى']
  ]),
  delRole: O([
    ['hod', 'Head of delegation', 'رئيس الوفد'], ['delegate', 'Delegate', 'عضو وفد'],
    ['observer', 'Observer', 'مراقب'], ['speaker', 'Speaker', 'متحدث'],
    ['moderator', 'Moderator', 'مدير جلسة'], ['secretariat', 'Secretariat', 'أمانة'],
    ['interpreter', 'Interpreter', 'مترجم فوري'], ['accompanying', 'Accompanying official', 'مرافق رسمي']
  ]),
  attendance: O([
    ['in_person', 'In person, in Cairo', 'حضورياً في القاهرة'],
    ['online', 'Online', 'عن بُعد']
  ]),
  interp: O([
    ['ar', 'Arabic', 'العربية'], ['en', 'English', 'الإنجليزية'],
    ['fr', 'French', 'الفرنسية'], ['es', 'Spanish', 'الإسبانية'],
    ['none', 'None required', 'لا حاجة']
  ]),
  duration: O([['10', '10 minutes', '10 دقائق'], ['15', '15 minutes', '15 دقيقة'], ['20', '20 minutes', '20 دقيقة'], ['30', '30 minutes', '30 دقيقة']]),
  av: O([
    ['laptop', 'Own laptop (HDMI)', 'حاسوب شخصي (HDMI)'],
    ['sound', 'Video with sound', 'فيديو بالصوت'],
    ['internet', 'Live internet access', 'اتصال إنترنت مباشر'],
    ['clicker', 'Presenter remote', 'جهاز تحكم بالعرض'],
    ['none', 'Nothing beyond the standard setup', 'لا شيء إضافي']
  ]),
  passportType: O([
    ['diplomatic', 'Diplomatic', 'دبلوماسي'], ['service', 'Service or special', 'خاص أو مهمة'],
    ['ordinary', 'Ordinary', 'عادي'], ['lp', 'UN laissez-passer', 'جواز مرور أممي']
  ]),
  terminal: O([['T1', 'Terminal 1', 'الصالة 1'], ['T2', 'Terminal 2', 'الصالة 2'], ['T3', 'Terminal 3', 'الصالة 3'], ['unknown', 'Not known yet', 'غير معروفة بعد']]),
  accomType: O([
    ['official', 'One of the official hotels', 'أحد الفنادق الرسمية'],
    ['own', 'Accommodation I arrange myself', 'إقامة أرتبها بنفسي']
  ]),
  roomType: O([['single', 'Single', 'مفردة'], ['double', 'Double', 'مزدوجة'], ['suite', 'Suite', 'جناح']]),
  paidBy: O([
    ['institution', 'My own institution', 'جهة عملي'], ['self', 'Myself', 'على نفقتي'],
    ['host', 'The host (ASA)', 'الجهة المضيفة'], ['donor', 'A donor or sponsor', 'جهة مانحة أو راعية']
  ]),
  dietary: O([
    ['none', 'No special requirement', 'لا متطلبات'], ['vegetarian', 'Vegetarian', 'نباتي'],
    ['vegan', 'Vegan', 'نباتي صرف'], ['halal', 'Halal only', 'حلال فقط'],
    ['gluten', 'Gluten free', 'خالٍ من الجلوتين'], ['diabetic', 'Diabetic', 'مناسب لمرضى السكري'],
    ['other', 'Other', 'أخرى']
  ]),
  access: O([
    ['none', 'None', 'لا يوجد'], ['wheelchair', 'Wheelchair access', 'إتاحة لكرسي متحرك'],
    ['ground', 'Ground-floor room', 'غرفة بالدور الأرضي'], ['sign', 'Sign language interpretation', 'ترجمة بلغة الإشارة'],
    ['print', 'Large-print materials', 'مواد بخط كبير'], ['other', 'Other', 'أخرى']
  ]),
  accRel: O([
    ['spouse', 'Spouse', 'زوج/زوجة'], ['aide', 'Aide or assistant', 'مساعد'],
    ['security', 'Security', 'مرافقة أمنية'], ['interpreter', 'Interpreter', 'مترجم'],
    ['other', 'Other', 'أخرى']
  ]),
  yesno: O([['yes', 'Yes', 'نعم'], ['no', 'No', 'لا']])
};

const isYes = (v) => v === 'yes';
/* In-person sections stay visible until the delegate explicitly chooses online,
   so the section index does not shrink and grow under them. */
const inPerson = (d) => d.attendance_mode !== 'online';
const online = (d) => d.attendance_mode === 'online';

/* ---------------------------------------------------------------------------
   4. FORM SCHEMA
   Field keys match the developer specification exactly.
   t: text|email|tel|date|time|number|textarea|select|radio|multi|check|file|note
   --------------------------------------------------------------------------- */
const SCHEMA = [

/* --- 1. Personal ------------------------------------------------------- */
{
  id: 'personal',
  title: { en: 'Personal information', ar: 'البيانات الشخصية' },
  desc: { en: 'Names must be written exactly as they appear in your passport. They are used for accreditation and, where requested, for your visa facilitation letter.', ar: 'تُكتب الأسماء كما وردت في جواز السفر تماماً، لأنها تُستخدم في الاعتماد وفي خطاب تسهيل التأشيرة عند طلبه.' },
  fields: [
    { k: 'salutation', t: 'select', req: true, opts: OPT.salutation, l: { en: 'Salutation', ar: 'اللقب' } },
    { k: 'gender', t: 'select', opts: OPT.gender, l: { en: 'Gender', ar: 'النوع' } },
    { k: 'first_name_passport', t: 'text', req: true, min: 2, max: 50, l: { en: 'First name, as in passport', ar: 'الاسم الأول كما في الجواز' } },
    { k: 'middle_name_passport', t: 'text', max: 60, l: { en: 'Middle name', ar: 'الاسم الأوسط' } },
    { k: 'family_name_passport', t: 'text', req: true, min: 2, max: 50, l: { en: 'Family name, as in passport', ar: 'اسم العائلة كما في الجواز' } },
    { k: 'full_name_arabic', t: 'text', max: 80, l: { en: 'Full name in Arabic', ar: 'الاسم بالكامل بالعربية' }, hint: { en: 'Used on your badge and in protocol lists.', ar: 'يُستخدم على البادج وفي كشوف البروتوكول.' } },
    { k: 'badge_name_en', t: 'text', min: 3, max: 40, l: { en: 'Name on badge', ar: 'الاسم على البادج' }, hint: { en: 'Filled in from your passport name. Shorten it if you prefer.', ar: 'يُملأ من اسم الجواز. يمكنك اختصاره.' } },
    { k: 'badge_name_ar', t: 'text', max: 40, l: { en: 'Name on badge in Arabic', ar: 'الاسم على البادج بالعربية' } },
    { k: 'date_of_birth', t: 'date', req: true, rule: 'dob', l: { en: 'Date of birth', ar: 'تاريخ الميلاد' } },
    { k: 'place_of_birth', t: 'text', reqIf: (d) => isYes(d.visa_letter_needed), l: { en: 'Place of birth', ar: 'محل الميلاد' }, hint: { en: 'Needed for the visa facilitation letter.', ar: 'مطلوب لخطاب تسهيل التأشيرة.' } },
    { k: 'nationality', t: 'select', req: true, opts: COUNTRIES, l: { en: 'Nationality', ar: 'الجنسية' } },
    { k: 'email', t: 'email', req: true, ro: true, l: { en: 'Email', ar: 'البريد الإلكتروني' }, hint: { en: 'Verified at the start. Contact the secretariat to change it.', ar: 'تم التحقق منه في البداية. راسل الأمانة لتغييره.' } },
    { k: 'alt_email', t: 'email', l: { en: 'Alternative email', ar: 'بريد إلكتروني بديل' } },
    { k: 'mobile', t: 'tel', req: true, rule: 'phone', l: { en: 'Mobile, with country code', ar: 'المحمول مع رمز الدولة' }, ph: '+20 100 000 0000' },
    { k: 'whatsapp_same', t: 'check', l: { en: 'This number is also on WhatsApp', ar: 'هذا الرقم متاح على واتساب' }, hint: { en: 'The secretariat runs a WhatsApp group for on-the-ground coordination.', ar: 'تدير الأمانة مجموعة واتساب للتنسيق الميداني.' } },
    { k: 'whatsapp_number', t: 'tel', rule: 'phone', showIf: (d) => !d.whatsapp_same, l: { en: 'WhatsApp number', ar: 'رقم واتساب' } },
    { k: 'correspondence_language', t: 'select', opts: OPT.corrLang, l: { en: 'Language for correspondence', ar: 'لغة المراسلات' } }
  ]
},

/* --- 2. Institution ---------------------------------------------------- */
{
  id: 'institution',
  title: { en: 'Institution and delegation', ar: 'الجهة والصفة التمثيلية' },
  desc: { en: 'Your institution, your role in the delegation, and the liaison officer who nominated you. The secretariat matches every registration against the nomination received from your institution.', ar: 'جهة عملك وصفتك في الوفد وضابط الاتصال الذي رشّحك. تطابق الأمانة كل تسجيل مع الترشيح الوارد من جهتك.' },
  fields: [
    { k: 'organization_name', t: 'text', req: true, wide: true, l: { en: 'SAI or organisation', ar: 'الجهة الرقابية أو المؤسسة' } },
    { k: 'organization_type', t: 'select', req: true, opts: OPT.orgType, l: { en: 'Type of organisation', ar: 'نوع الجهة' } },
    { k: 'regional_group', t: 'select', req: true, opts: OPT.region, l: { en: 'INTOSAI regional group', ar: 'المجموعة الإقليمية' } },
    { k: 'country', t: 'select', req: true, opts: COUNTRIES, l: { en: 'Country', ar: 'الدولة' } },
    { k: 'job_title', t: 'text', req: true, min: 3, max: 100, l: { en: 'Job title', ar: 'المسمى الوظيفي' }, hint: { en: 'Printed on your badge and in the delegates list.', ar: 'يُطبع على البادج وفي كشف المشاركين.' } },
    { k: 'department', t: 'text', max: 100, l: { en: 'Department', ar: 'الإدارة' } },
    { k: 'protocol_level', t: 'select', req: true, opts: OPT.protocol, l: { en: 'Protocol level', ar: 'المستوى البروتوكولي' }, hint: { en: 'Determines seating, name plates and reception arrangements.', ar: 'يحدد ترتيب الجلوس ولوحات الأسماء والاستقبال.' } },
    { k: 'role_in_delegation', t: 'select', req: true, opts: OPT.delRole, l: { en: 'Role in the delegation', ar: 'الصفة في الوفد' } },
    { k: 'liaison_officer_name', t: 'text', req: true, l: { en: 'Nominating liaison officer', ar: 'ضابط الاتصال المرشِّح' } },
    { k: 'liaison_officer_email', t: 'email', req: true, l: { en: 'Liaison officer email', ar: 'بريد ضابط الاتصال' }, hint: { en: 'A copy of your confirmation is sent to this address.', ar: 'تُرسل نسخة من التأكيد إلى هذا العنوان.' } },
    { k: 'nomination_letter_ref', t: 'text', l: { en: 'Nomination letter reference', ar: 'رقم خطاب الترشيح' } },
    { k: 'attendance_mode', t: 'radio', req: true, wide: true, opts: OPT.attendance, l: { en: 'How will you attend?', ar: 'كيف ستحضر؟' }, hint: { en: 'Travel, visa and hotel sections appear only for in-person attendance.', ar: 'تظهر أقسام السفر والتأشيرة والفندق للحضور الشخصي فقط.' } },
    { k: 'interpretation_language', t: 'multi', wide: true, opts: OPT.interp, l: { en: 'Interpretation you will need', ar: 'الترجمة الفورية التي تحتاجها' } },
    { k: 'has_aide', t: 'check', wide: true, l: { en: 'An aide or assistant is travelling with me', ar: 'يرافقني مساعد' } },
    { k: 'aide_name', t: 'text', reqIf: (d) => d.has_aide, showIf: (d) => d.has_aide, l: { en: 'Aide name', ar: 'اسم المساعد' }, hint: { en: 'Also register them in the accompanying persons section.', ar: 'سجّله أيضاً في قسم المرافقين.' } },
    { k: 'has_security_detail', t: 'check', wide: true, showIf: (d) => d.protocol_level === 'head', l: { en: 'A security detail is accompanying me', ar: 'ترافقني حماية أمنية' } },
    { k: 'security_detail_count', t: 'number', min: 1, max: 6, showIf: (d) => d.protocol_level === 'head' && d.has_security_detail, reqIf: (d) => d.has_security_detail, l: { en: 'Number of security personnel', ar: 'عدد أفراد الحماية' } }
  ]
},

/* --- 3. Contribution --------------------------------------------------- */
{
  id: 'contribution',
  title: { en: 'Speaking and contribution', ar: 'المساهمة العلمية' },
  desc: { en: 'Speaking slots are limited and confirmed by the secretariat after review. Requesting one here does not confirm it.', ar: 'عدد فرص التحدث محدود وتؤكدها الأمانة بعد المراجعة. الطلب هنا لا يعني التأكيد.' },
  fields: [
    { k: 'wants_to_present', t: 'radio', req: true, wide: true, opts: OPT.yesno, l: { en: 'Do you want to request a speaking slot?', ar: 'هل ترغب في طلب فرصة للتحدث؟' } },
    { k: 'presentation_title', t: 'text', wide: true, showIf: (d) => isYes(d.wants_to_present), reqIf: (d) => isYes(d.wants_to_present), min: 10, max: 150, l: { en: 'Presentation title', ar: 'عنوان العرض' } },
    { k: 'presentation_abstract', t: 'textarea', wide: true, showIf: (d) => isYes(d.wants_to_present), reqIf: (d) => isYes(d.wants_to_present), min: 200, max: 1500, count: true, l: { en: 'Abstract', ar: 'ملخص العرض' } },
    { k: 'presentation_duration', t: 'select', opts: OPT.duration, showIf: (d) => isYes(d.wants_to_present), reqIf: (d) => isYes(d.wants_to_present), l: { en: 'Duration you are requesting', ar: 'المدة المطلوبة' } },
    { k: 'av_requirements', t: 'multi', wide: true, opts: OPT.av, showIf: (d) => isYes(d.wants_to_present), l: { en: 'Technical requirements', ar: 'المتطلبات الفنية' } },
    { k: 'speaker_bio', t: 'textarea', wide: true, showIf: (d) => isYes(d.wants_to_present), reqIf: (d) => isYes(d.wants_to_present), min: 100, max: 800, count: true, l: { en: 'Short biography', ar: 'سيرة ذاتية مختصرة' }, hint: { en: 'Published on the event page if you consent to publication.', ar: 'تُنشر في صفحة الحدث إذا وافقت على النشر.' } },
    { k: 'speaker_photo', t: 'file', wide: true, accept: 'image', maxMB: 5, showIf: (d) => isYes(d.wants_to_present), l: { en: 'Portrait photo', ar: 'صورة شخصية' } },
    { k: 'is_prerecorded', t: 'check', wide: true, showIf: (d) => isYes(d.wants_to_present) && online(d), l: { en: 'My presentation will be pre-recorded', ar: 'سيكون عرضي مسجلاً مسبقاً' } },
    { k: 'slides_file', t: 'file', wide: true, accept: 'doc', maxMB: 50, showIf: (d) => isYes(d.wants_to_present), l: { en: 'Presentation slides', ar: 'ملف العرض' }, hint: { en: 'Optional now. You can upload them later using your edit link.', ar: 'اختياري الآن. يمكنك رفعه لاحقاً عبر رابط التعديل.' } }
  ]
},

/* --- 4. Passport ------------------------------------------------------- */
{
  id: 'passport',
  title: { en: 'Travel document', ar: 'وثيقة السفر' },
  desc: { en: 'Enter the details exactly as printed. Your passport number is encrypted and visible only to the accreditation officer.', ar: 'أدخل البيانات كما هي مطبوعة تماماً. رقم الجواز مشفّر ولا يطلع عليه سوى مسؤول الاعتماد.' },
  showIf: inPerson,
  fields: [
    { k: 'passport_number', t: 'text', req: true, min: 5, max: 15, l: { en: 'Passport number', ar: 'رقم الجواز' } },
    { k: 'passport_type', t: 'select', req: true, opts: OPT.passportType, l: { en: 'Passport type', ar: 'نوع الجواز' } },
    { k: 'passport_issuing_country', t: 'select', req: true, opts: COUNTRIES, l: { en: 'Issuing country', ar: 'دولة الإصدار' } },
    { k: 'passport_place_of_issue', t: 'text', req: true, l: { en: 'Place of issue', ar: 'محل الإصدار' } },
    { k: 'passport_issue_date', t: 'date', req: true, rule: 'past', l: { en: 'Date of issue', ar: 'تاريخ الإصدار' } },
    { k: 'passport_expiry_date', t: 'date', req: true, rule: 'expiry', l: { en: 'Date of expiry', ar: 'تاريخ الانتهاء' } },
    { k: 'passport_copy', t: 'file', wide: true, accept: 'any', maxMB: 10, reqIf: (d) => isYes(d.visa_letter_needed), l: { en: 'Copy of the passport data page', ar: 'صورة صفحة بيانات الجواز' }, hint: { en: 'Required only if you request a visa facilitation letter. Deleted 60 days after the meeting.', ar: 'مطلوبة فقط عند طلب خطاب تسهيل التأشيرة. تُحذف بعد 60 يوماً من الاجتماع.' } }
  ]
},

/* --- 5. Visa ----------------------------------------------------------- */
{
  id: 'visa',
  title: { en: 'Visa facilitation', ar: 'تسهيل التأشيرة' },
  desc: { en: 'The letter is issued to the passport details you entered in the previous section. Go back and correct them if anything is wrong.', ar: 'يصدر الخطاب ببيانات الجواز التي أدخلتها في القسم السابق. ارجع وصحّحها إن وُجد خطأ.' },
  showIf: inPerson,
  fields: [
    { k: 'visa_letter_needed', t: 'radio', req: true, wide: true, opts: OPT.yesno, l: { en: 'Do you need a visa facilitation letter?', ar: 'هل تحتاج خطاب تسهيل تأشيرة؟' }, hint: { en: 'Issued within five working days of approval.', ar: 'يصدر خلال خمسة أيام عمل من الاعتماد.' } },
    { k: 'visa_embassy_location', t: 'text', wide: true, showIf: (d) => isYes(d.visa_letter_needed), reqIf: (d) => isYes(d.visa_letter_needed), l: { en: 'Egyptian mission where you will apply', ar: 'البعثة المصرية التي ستتقدم إليها' }, ph: 'Egyptian Embassy, Nairobi' },
    { k: 'visa_on_arrival_intent', t: 'check', wide: true, showIf: (d) => isYes(d.visa_letter_needed), l: { en: 'I intend to obtain the visa on arrival at Cairo airport', ar: 'أنوي الحصول على التأشيرة عند الوصول لمطار القاهرة' } },
    { k: 'has_existing_visa', t: 'check', wide: true, l: { en: 'I already hold a valid Egyptian visa', ar: 'لديّ تأشيرة مصرية سارية' } },
    { k: 'visa_copy', t: 'file', wide: true, accept: 'any', maxMB: 10, showIf: (d) => d.has_existing_visa, reqIf: (d) => d.has_existing_visa, l: { en: 'Copy of the valid visa', ar: 'صورة التأشيرة السارية' } },
    { k: 'visa_details_confirmed', t: 'check', wide: true, showIf: (d) => isYes(d.visa_letter_needed), reqIf: (d) => isYes(d.visa_letter_needed), l: { en: 'I confirm that my name and passport number above match my passport exactly', ar: 'أؤكد أن اسمي ورقم جوازي أعلاه مطابقان لجواز سفري تماماً' } }
  ]
},

/* --- 6. Flights -------------------------------------------------------- */
{
  id: 'travel',
  title: { en: 'Flights and transfers', ar: 'الطيران والانتقالات' },
  desc: { en: 'Arrival airport is Cairo International. Flight details are optional now and can be added later, but the arrival terminal is what lets the welcome team find you.', ar: 'مطار الوصول هو القاهرة الدولي. بيانات الرحلة اختيارية الآن ويمكن إضافتها لاحقاً، لكن صالة الوصول هي ما يمكّن فريق الاستقبال من الوصول إليك.' },
  showIf: inPerson,
  fields: [
    { k: 'arrival_airline', t: 'text', l: { en: 'Arrival airline', ar: 'شركة الطيران عند الوصول' } },
    { k: 'arrival_flight_no', t: 'text', max: 8, l: { en: 'Arrival flight number', ar: 'رقم رحلة الوصول' }, ph: 'MS 852' },
    { k: 'arrival_date', t: 'date', l: { en: 'Arrival date', ar: 'تاريخ الوصول' } },
    { k: 'arrival_time', t: 'time', l: { en: 'Arrival time, Cairo local', ar: 'وقت الوصول بتوقيت القاهرة' } },
    { k: 'arrival_terminal', t: 'select', opts: OPT.terminal, wide: true, l: { en: 'Arrival terminal', ar: 'صالة الوصول' } },
    {
      k: 'connecting_flights', t: 'repeat', wide: true,
      itemLabel: { en: 'Connecting flight', ar: 'رحلة ترانزيت' },
      addLabel: { en: 'Add a connecting flight', ar: 'إضافة رحلة ترانزيت' },
      sub: [
        { k: 'cf_via_airport', t: 'text', l: { en: 'Via airport', ar: 'عبر مطار' } },
        { k: 'cf_airline', t: 'text', l: { en: 'Airline', ar: 'شركة الطيران' } },
        { k: 'cf_flight_no', t: 'text', max: 8, l: { en: 'Flight number', ar: 'رقم الرحلة' } },
        { k: 'cf_date', t: 'date', l: { en: 'Date', ar: 'التاريخ' } },
        { k: 'cf_time', t: 'time', l: { en: 'Time', ar: 'الوقت' } }
      ]
    },
    { k: 'departure_airline', t: 'text', l: { en: 'Departure airline', ar: 'شركة طيران المغادرة' } },
    { k: 'departure_flight_no', t: 'text', max: 8, l: { en: 'Departure flight number', ar: 'رقم رحلة المغادرة' } },
    { k: 'departure_date', t: 'date', l: { en: 'Departure date', ar: 'تاريخ المغادرة' } },
    { k: 'departure_time', t: 'time', l: { en: 'Departure time', ar: 'وقت المغادرة' } },
    { k: 'departure_terminal', t: 'select', opts: OPT.terminal, wide: true, l: { en: 'Departure terminal', ar: 'صالة المغادرة' } },
    { k: 'airport_pickup_required', t: 'radio', req: true, wide: true, opts: OPT.yesno, l: { en: 'Do you need a pickup from the airport?', ar: 'هل تحتاج توصيلاً من المطار؟' } },
    { k: 'airport_dropoff_required', t: 'radio', req: true, wide: true, opts: OPT.yesno, l: { en: 'Do you need a drop-off to the airport?', ar: 'هل تحتاج توصيلاً إلى المطار؟' } },
    { k: 'luggage_count', t: 'number', min: 0, max: 10, showIf: (d) => isYes(d.airport_pickup_required), l: { en: 'Pieces of luggage', ar: 'عدد الحقائب' }, hint: { en: 'Used to size the vehicle.', ar: 'لتحديد حجم المركبة.' } },
    { k: 'ticket_file', t: 'file', wide: true, accept: 'any', maxMB: 10, l: { en: 'Flight itinerary', ar: 'خط سير الرحلة' } }
  ]
},

/* --- 7. Accommodation -------------------------------------------------- */
{
  id: 'accommodation',
  title: { en: 'Accommodation', ar: 'الإقامة' },
  desc: { en: 'The official hotels offer a negotiated delegate rate and a shuttle to the venue. If you stay elsewhere, the secretariat still needs the address to plan transport.', ar: 'تقدم الفنادق الرسمية سعراً متفاوضاً عليه للمندوبين وحافلة إلى مقر الاجتماع. إذا أقمت في مكان آخر فالأمانة تحتاج العنوان لتخطيط الانتقالات.' },
  showIf: inPerson,
  fields: [
    { k: 'accommodation_type', t: 'radio', req: true, wide: true, opts: OPT.accomType, l: { en: 'Where will you stay?', ar: 'أين ستقيم؟' } },
    { k: 'official_hotel', t: 'select', opts: [], dynamic: 'hotels', showIf: (d) => d.accommodation_type === 'official', reqIf: (d) => d.accommodation_type === 'official', l: { en: 'Official hotel', ar: 'الفندق الرسمي' } },
    { k: 'room_type', t: 'select', opts: OPT.roomType, showIf: (d) => d.accommodation_type === 'official', reqIf: (d) => d.accommodation_type === 'official', l: { en: 'Room type', ar: 'نوع الغرفة' } },
    { k: 'own_hotel_name_address', t: 'textarea', wide: true, showIf: (d) => d.accommodation_type === 'own', reqIf: (d) => d.accommodation_type === 'own', l: { en: 'Hotel name and address', ar: 'اسم الفندق وعنوانه' } },
    { k: 'check_in_date', t: 'date', reqIf: (d) => !!d.accommodation_type, l: { en: 'Check-in', ar: 'تاريخ الوصول للفندق' } },
    { k: 'check_out_date', t: 'date', rule: 'checkout', reqIf: (d) => !!d.accommodation_type, l: { en: 'Check-out', ar: 'تاريخ المغادرة' } },
    { k: 'booking_reference', t: 'text', l: { en: 'Booking reference, if already booked', ar: 'رقم الحجز إن وُجد' } },
    { k: 'room_paid_by', t: 'select', req: true, opts: OPT.paidBy, l: { en: 'Who pays for the room?', ar: 'من يتحمل تكلفة الغرفة؟' } },
    { k: 'shuttle_required', t: 'radio', req: true, wide: true, opts: OPT.yesno, l: { en: 'Do you need the shuttle between hotel and venue?', ar: 'هل تحتاج الحافلة بين الفندق ومقر الاجتماع؟' } }
  ]
},

/* --- 8. Emergency, health and dietary ---------------------------------- */
{
  id: 'welfare',
  title: { en: 'Emergency contact and requirements', ar: 'جهة الطوارئ والاحتياجات' },
  showIf: inPerson,
  desc: { en: 'The emergency contact is mandatory. Everything below it is optional, held encrypted, and seen only by the registrar. It is never included in any delegate list or export.', ar: 'جهة الاتصال للطوارئ إلزامية. وما دونها اختياري ويُحفظ مشفراً ولا يطلع عليه سوى مسؤول التسجيل، ولا يظهر في أي كشف أو تصدير.' },
  fields: [
    { k: 'emergency_contact_name', t: 'text', req: true, l: { en: 'Emergency contact name', ar: 'اسم جهة الاتصال للطوارئ' } },
    { k: 'emergency_contact_relation', t: 'text', req: true, l: { en: 'Relationship to you', ar: 'صلته بك' } },
    { k: 'emergency_contact_phone', t: 'tel', req: true, rule: 'phone', l: { en: 'Emergency contact phone', ar: 'هاتف جهة الطوارئ' } },
    { k: 'emergency_contact_email', t: 'email', l: { en: 'Emergency contact email', ar: 'بريد جهة الطوارئ' } },
    { k: 'dietary_requirements', t: 'multi', wide: true, opts: OPT.dietary, l: { en: 'Dietary requirements', ar: 'المتطلبات الغذائية' } },
    { k: 'dietary_notes', t: 'textarea', wide: true, max: 300, showIf: (d) => Array.isArray(d.dietary_requirements) && d.dietary_requirements.includes('other'), l: { en: 'Dietary notes', ar: 'ملاحظات غذائية' } },
    { k: 'allergies', t: 'textarea', wide: true, max: 300, l: { en: 'Allergies', ar: 'الحساسية' } },
    { k: 'medical_notes_emergency', t: 'textarea', wide: true, max: 500, l: { en: 'Medical information relevant in an emergency', ar: 'معلومات طبية تهم في حالات الطوارئ' }, hint: { en: 'Only what a first responder in Cairo would need to know.', ar: 'فقط ما يحتاج مسعف في القاهرة معرفته.' } },
    { k: 'accessibility_needs', t: 'multi', wide: true, opts: OPT.access, l: { en: 'Accessibility needs', ar: 'احتياجات الإتاحة' } },
    { k: 'accessibility_notes', t: 'textarea', wide: true, max: 300, showIf: (d) => Array.isArray(d.accessibility_needs) && d.accessibility_needs.includes('other'), l: { en: 'Accessibility notes', ar: 'ملاحظات الإتاحة' } },
    { k: 'travel_insurance', t: 'radio', wide: true, opts: OPT.yesno, showIf: inPerson, l: { en: 'Do you hold valid travel or medical insurance for this trip?', ar: 'هل لديك تأمين سفر أو طبي ساري لهذه الرحلة؟' } }
  ]
},

/* --- 9. Accompanying persons ------------------------------------------- */
{
  id: 'accompanying',
  title: { en: 'Accompanying persons', ar: 'المرافقون' },
  desc: { en: 'Register everyone travelling with you, including aides and security. There is no limit on the number, but each person is approved separately.', ar: 'سجّل كل من يسافر معك، بمن فيهم المساعدون والحماية. لا يوجد حد للعدد، لكن كل شخص يُعتمد على حدة.' },
  showIf: inPerson,
  fields: [
    { k: 'is_accompanied', t: 'radio', req: true, wide: true, opts: OPT.yesno, l: { en: 'Is anyone travelling with you?', ar: 'هل يرافقك أحد؟' } },
    {
      k: 'accompanying', t: 'repeat', wide: true, showIf: (d) => isYes(d.is_accompanied),
      itemLabel: { en: 'Accompanying person', ar: 'مرافق' },
      addLabel: { en: 'Add an accompanying person', ar: 'إضافة مرافق' },
      sub: [
        { k: 'acc_full_name_passport', t: 'text', req: true, l: { en: 'Full name, as in passport', ar: 'الاسم كما في الجواز' } },
        { k: 'acc_name_on_badge', t: 'text', req: true, l: { en: 'Name on badge', ar: 'الاسم على البادج' } },
        { k: 'acc_relationship', t: 'select', req: true, opts: OPT.accRel, l: { en: 'Relationship', ar: 'الصفة' } },
        { k: 'acc_nationality', t: 'select', req: true, opts: COUNTRIES, l: { en: 'Nationality', ar: 'الجنسية' } },
        { k: 'acc_date_of_birth', t: 'date', req: true, l: { en: 'Date of birth', ar: 'تاريخ الميلاد' } },
        { k: 'acc_passport_number', t: 'text', req: true, min: 5, max: 15, l: { en: 'Passport number', ar: 'رقم الجواز' } },
        { k: 'acc_passport_expiry_date', t: 'date', req: true, l: { en: 'Passport expiry', ar: 'انتهاء الجواز' } },
        { k: 'acc_visa_letter_needed', t: 'radio', req: true, opts: OPT.yesno, l: { en: 'Visa letter needed?', ar: 'هل يحتاج خطاب تأشيرة؟' } },
        { k: 'acc_passport_copy', t: 'file', accept: 'any', maxMB: 10, l: { en: 'Passport copy', ar: 'صورة الجواز' } },
        { k: 'acc_attends_sessions', t: 'radio', req: true, opts: OPT.yesno, l: { en: 'Attending the official sessions?', ar: 'هل يحضر الجلسات الرسمية؟' } },
        { k: 'acc_attends_social', t: 'radio', req: true, opts: OPT.yesno, l: { en: 'Attending the social programme?', ar: 'هل يحضر البرنامج الاجتماعي؟' } },
        { k: 'acc_dietary', t: 'multi', opts: OPT.dietary, l: { en: 'Dietary requirements', ar: 'المتطلبات الغذائية' } }
      ]
    }
  ]
},

/* --- 10. Social programme ---------------------------------------------- */
{
  id: 'programme',
  title: { en: 'Social programme', ar: 'البرنامج الاجتماعي' },
  desc: { en: 'Headcounts are given to the venue and the caterer a week in advance, so an accurate answer here matters more than it looks.', ar: 'تُسلَّم الأعداد للمقر ومتعهد الضيافة قبل أسبوع، فدقة الإجابة هنا أهم مما تبدو.' },
  showIf: inPerson,
  fields: [
    { k: 'attend_welcome_reception', t: 'radio', req: true, wide: true, opts: OPT.yesno, l: { en: 'Welcome reception', ar: 'حفل الاستقبال' } },
    { k: 'attend_official_dinner', t: 'radio', req: true, wide: true, opts: OPT.yesno, l: { en: 'Official dinner', ar: 'العشاء الرسمي' } },
    { k: 'attend_cultural_tour', t: 'radio', wide: true, opts: OPT.yesno, l: { en: 'Cultural tour', ar: 'الجولة الثقافية' } },
    { k: 'needs_local_sim', t: 'check', wide: true, l: { en: 'I would like help getting a local SIM card', ar: 'أرغب في المساعدة للحصول على شريحة اتصال محلية' } },
    { k: 'notes_to_secretariat', t: 'textarea', wide: true, max: 1000, count: true, l: { en: 'Anything else the secretariat should know', ar: 'أي شيء آخر ينبغي أن تعرفه الأمانة' } }
  ]
},

/* --- 11. Online participation ------------------------------------------ */
{
  id: 'online',
  title: { en: 'Joining online', ar: 'المشاركة عن بُعد' },
  desc: { en: 'The connection link is sent to your registered email once your registration is approved.', ar: 'يُرسل رابط الاتصال إلى بريدك المسجل بعد اعتماد تسجيلك.' },
  showIf: online,
  fields: [
    { k: 'timezone', t: 'text', req: true, wide: true, l: { en: 'Your time zone', ar: 'منطقتك الزمنية' }, hint: { en: 'Detected automatically. Correct it if it is wrong.', ar: 'تُكتشف تلقائياً. صحّحها إذا كانت خاطئة.' } },
    { k: 'accessibility_needs', t: 'multi', wide: true, opts: OPT.access, l: { en: 'Accessibility needs', ar: 'احتياجات الإتاحة' }, hint: { en: 'Sign language, captions or large-print materials for the online sessions.', ar: 'ترجمة بلغة الإشارة أو تعليقات نصية أو مواد بخط كبير للجلسات عن بُعد.' } },
    { k: 'accessibility_notes', t: 'textarea', wide: true, max: 300, showIf: (d) => Array.isArray(d.accessibility_needs) && d.accessibility_needs.includes('other'), l: { en: 'Accessibility notes', ar: 'ملاحظات الإتاحة' } },
    { k: 'requests_test_session', t: 'check', wide: true, l: { en: 'I would like a connection test before the meeting', ar: 'أرغب في اختبار للاتصال قبل الاجتماع' } },
    { k: 'consent_recording', t: 'check', wide: true, req: true, l: { en: 'I understand the sessions are recorded and consent to appearing in the recording', ar: 'أعلم أن الجلسات تُسجَّل وأوافق على ظهوري في التسجيل' } }
  ]
},

/* --- 12. Consents ------------------------------------------------------ */
{
  id: 'consents',
  title: { en: 'Consent and declaration', ar: 'الموافقات والإقرار' },
  desc: { en: 'Each consent is separate and recorded with its timestamp. The two optional ones below change nothing about your registration if you decline them.', ar: 'كل موافقة مستقلة وتُسجَّل بتوقيتها. الموافقتان الاختياريتان أدناه لا تغيّران شيئاً في تسجيلك إذا رفضتهما.' },
  fields: [
    { k: 'consent_processing', t: 'check', wide: true, req: true, l: { en: 'I consent to the organising secretariat processing this data for accreditation and meeting logistics.', ar: 'أوافق على معالجة أمانة التنظيم لهذه البيانات لأغراض الاعتماد والترتيبات اللوجستية.' } },
    { k: 'consent_visa_sharing', t: 'check', wide: true, showIf: (d) => isYes(d.visa_letter_needed), reqIf: (d) => isYes(d.visa_letter_needed), l: { en: 'I consent to my passport details being shared with the Egyptian Ministry of Foreign Affairs and immigration authorities for visa facilitation.', ar: 'أوافق على مشاركة بيانات جوازي مع وزارة الخارجية المصرية وجهات الجوازات لتسهيل التأشيرة.' } },
    { k: 'consent_hotel_sharing', t: 'check', wide: true, showIf: (d) => d.accommodation_type === 'official', reqIf: (d) => d.accommodation_type === 'official', l: { en: 'I consent to my name and stay dates being shared with the official hotel.', ar: 'أوافق على مشاركة اسمي وتواريخ إقامتي مع الفندق الرسمي.' } },
    { k: 'consent_media', t: 'check', wide: true, l: { en: 'I consent to photographs and video in which I appear being published on the event media page.', ar: 'أوافق على نشر الصور ومقاطع الفيديو التي أظهر فيها على صفحة وسائط الحدث.' }, hint: { en: 'Optional.', ar: 'اختياري.' } },
    { k: 'consent_delegate_list', t: 'check', wide: true, l: { en: 'I consent to my name, title and organisation appearing in the delegates list circulated to participants.', ar: 'أوافق على إدراج اسمي ووظيفتي وجهتي في كشف المشاركين المتداول.' }, hint: { en: 'Optional.', ar: 'اختياري.' } },
    { k: 'declaration_accuracy', t: 'check', wide: true, req: true, l: { en: 'I declare that the information given is accurate and matches my official travel documents.', ar: 'أقر بصحة البيانات المقدمة ومطابقتها لوثائق سفري الرسمية.' } },
    { k: 'signature_typed_name', t: 'text', wide: true, req: true, l: { en: 'Type your full name as a signature', ar: 'اكتب اسمك بالكامل كتوقيع' } },
    { k: 'privacy_note', t: 'note', wide: true, body: { en: 'Passport and visa files are deleted 60 days after the meeting. Health and dietary information is deleted after 30 days. The core registration record is kept for five years as an institutional archive. To exercise your data rights, write to the secretariat.', ar: 'تُحذف ملفات الجواز والتأشيرة بعد 60 يوماً من الاجتماع، والبيانات الصحية والغذائية بعد 30 يوماً. ويُحتفظ بسجل التسجيل الأساسي خمس سنوات كأرشيف مؤسسي. لممارسة حقوقك على بياناتك راسل الأمانة.' } }
  ]
}

];

/* =============================================================================
   5. STATE
   ============================================================================= */
const state = {
  lang: 'en',
  event: null,
  screen: 'gate',        // gate | otp | form | review | done | closed
  idx: 0,
  data: {},
  files: {},             // key -> File (never persisted to the device draft)
  errors: {},
  touched: false,
  startedAt: Date.now(),
  otpEmail: '',
  session: '',
  reference: ''
};

/* Device draft. Falls back to memory when storage is blocked. */
const store = (() => {
  let ok = true, mem = {};
  try { localStorage.setItem('__t', '1'); localStorage.removeItem('__t'); } catch (e) { ok = false; }
  return {
    ok,
    get(k) { try { return ok ? localStorage.getItem(k) : (mem[k] ?? null); } catch (e) { return null; } },
    set(k, v) { try { ok ? localStorage.setItem(k, v) : (mem[k] = v); } catch (e) { } },
    del(k) { try { ok ? localStorage.removeItem(k) : delete mem[k]; } catch (e) { } }
  };
})();

function saveDraft() {
  const clean = {};
  for (const [k, v] of Object.entries(state.data)) {
    if (SENSITIVE.has(k)) continue;
    if (Array.isArray(v) && v.length && typeof v[0] === 'object') {
      clean[k] = v.map(row => {
        const r = {};
        for (const [sk, sv] of Object.entries(row)) if (!SENSITIVE.has(sk)) r[sk] = sv;
        return r;
      });
    } else clean[k] = v;
  }
  store.set(CONFIG.draftKey, JSON.stringify({ ev: state.event.code, at: Date.now(), data: clean }));
}
function loadDraft() {
  try {
    const raw = store.get(CONFIG.draftKey); if (!raw) return;
    const d = JSON.parse(raw);
    if (d.ev === state.event.code && Date.now() - d.at < 30 * 864e5) Object.assign(state.data, d.data);
  } catch (e) { }
}

/* =============================================================================
   6. VALIDATION
   ============================================================================= */
const RE = {
  email: /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/,
  code: /^ASA-[A-Z0-9]{3,10}-[A-Z]{2,4}-[A-Z0-9]{4}$/,
  phone: /^\+[1-9]\d{6,15}$/
};
const FREE_MAIL = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'live.com', 'icloud.com', 'aol.com', 'proton.me', 'protonmail.com', 'mail.ru', 'yandex.com', 'gmx.com'];
const DISPOSABLE = ['mailinator.com', 'guerrillamail.com', '10minutemail.com', 'tempmail.com', 'yopmail.com', 'trashmail.com', 'sharklasers.com'];
const domainOf = (e) => String(e || '').split('@')[1]?.toLowerCase() || '';

const ACCEPT = {
  any: ['application/pdf', 'image/jpeg', 'image/png'],
  image: ['image/jpeg', 'image/png'],
  doc: ['application/pdf', 'application/vnd.openxmlformats-officedocument.presentationml.presentation']
};

function isRequired(f, d) { return !!(f.req || (f.reqIf && f.reqIf(d))); }
function isVisible(f, d) { return !f.showIf || f.showIf(d); }

function validateField(f, d, scope) {
  const v = scope[f.k];
  const req = isRequired(f, d);
  const empty = v === undefined || v === null || v === '' || (Array.isArray(v) && !v.length) || (f.t === 'check' && !v);
  if (f.t === 'file') {
    const file = state.files[f.k];
    if (req && !file) return T('errRequired');
    if (file) {
      const allow = ACCEPT[f.accept || 'any'];
      if (allow && !allow.includes(file.type)) return T('errFileType');
      if (file.size > (f.maxMB || 10) * 1048576) return T('errFileSize');
    }
    return null;
  }
  if (empty) return req ? T('errRequired') : null;

  if (f.t === 'email' && !RE.email.test(v)) return T('errEmail');
  if (f.rule === 'phone' && !RE.phone.test(String(v).replace(/[\s()-]/g, ''))) return T('errPhone');
  if (f.t !== 'number') {
    if (f.min && typeof v === 'string' && v.length < f.min) return T('errMinLen');
    if (f.max && typeof v === 'string' && v.length > f.max) return T('errMaxLen');
  }
  if (f.rule === 'dob') {
    const age = (Date.now() - new Date(v)) / 3.156e10;
    if (!(age >= 18 && age <= 100)) return T('errAge');
  }
  if (f.rule === 'past' && new Date(v) > new Date()) return T('errDate');
  if (f.rule === 'expiry' && new Date(v) <= new Date(state.event.endDate)) return T('errDate');
  if (f.rule === 'checkout' && d.check_in_date && new Date(v) <= new Date(d.check_in_date)) return T('errCheckout');
  return null;
}

function validateSection(sec) {
  const errs = {};
  for (const f of sec.fields) {
    if (!isVisible(f, state.data)) continue;
    if (f.t === 'repeat') {
      const rows = state.data[f.k] || [];
      rows.forEach((row, i) => {
        for (const sf of f.sub) {
          const e = validateField(sf, state.data, row);
          if (e) errs[`${f.k}.${i}.${sf.k}`] = e;
        }
      });
      continue;
    }
    const e = validateField(f, state.data, state.data);
    if (e) errs[f.k] = e;
  }
  return errs;
}

/* Soft warning: passport validity shorter than six months after the meeting. */
function passportWarning() {
  const v = state.data.passport_expiry_date; if (!v) return null;
  const limit = new Date(state.event.endDate); limit.setMonth(limit.getMonth() + 6);
  return new Date(v) < limit ? T('warnPassport') : null;
}

/* =============================================================================
   7. DOM HELPERS
   ============================================================================= */
function el(tag, attrs = {}, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === false || v === null || v === undefined) continue;
    if (k === 'class') n.className = v;
    else if (k === 'html') n.innerHTML = v;
    else if (k.startsWith('on')) n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v === true ? '' : v);
  }
  for (const c of kids.flat()) if (c !== null && c !== undefined && c !== false) n.append(c.nodeType ? c : document.createTextNode(c));
  return n;
}
const clear = (n) => { while (n.firstChild) n.removeChild(n.firstChild); };

/* =============================================================================
   8. FIELD RENDERING
   ============================================================================= */
function optionsFor(f) {
  if (f.dynamic === 'hotels') return (state.event.hotels || []).map(h => ({ v: h, l: { en: h, ar: h } }));
  return f.opts || [];
}

function renderField(f, scope, path) {
  if (!isVisible(f, state.data)) return null;
  const id = 'fld_' + path.replace(/\./g, '_');
  const err = state.errors[path];
  const req = isRequired(f, state.data);
  const wrap = el('div', { class: 'f' + (f.wide || f.t === 'textarea' || f.t === 'repeat' ? ' wide' : '') });

  if (f.t === 'note') { wrap.append(el('div', { class: 'notice' }, L(f.body))); return wrap; }

  const labelText = [L(f.l), req ? el('span', { class: 'req', title: T('required') }, '*') : null];

  /* --- checkbox --- */
  if (f.t === 'check') {
    const cb = el('input', { type: 'checkbox', id, checked: !!scope[f.k] });
    cb.addEventListener('change', () => { scope[f.k] = cb.checked; onChange(true); });
    const lab = el('label', { class: 'choice' + (scope[f.k] ? ' on' : ''), for: id }, cb,
      el('span', { class: 't' }, ...labelText, f.hint ? el('span', { class: 'd' }, L(f.hint)) : null));
    wrap.append(lab);
    if (err) wrap.append(el('div', { class: 'err' }, err));
    return wrap;
  }

  /* --- radio / multi --- */
  if (f.t === 'radio' || f.t === 'multi') {
    const fs = el('fieldset');
    fs.append(el('legend', {}, ...labelText));
    if (f.hint) fs.append(el('div', { class: 'hint' }, L(f.hint)));
    const box = el('div', { class: 'choices' + (f.t === 'multi' || optionsFor(f).length > 3 ? ' inline' : '') });
    const current = scope[f.k];
    for (const o of optionsFor(f)) {
      const on = f.t === 'radio' ? current === o.v : Array.isArray(current) && current.includes(o.v);
      const inp = el('input', { type: f.t === 'radio' ? 'radio' : 'checkbox', name: id, checked: on });
      inp.addEventListener('change', () => {
        if (f.t === 'radio') scope[f.k] = o.v;
        else {
          const arr = Array.isArray(scope[f.k]) ? scope[f.k].slice() : [];
          const i = arr.indexOf(o.v);
          i > -1 ? arr.splice(i, 1) : arr.push(o.v);
          scope[f.k] = arr;
        }
        onChange(true);
      });
      box.append(el('label', { class: 'choice' + (on ? ' on' : '') }, inp, el('span', { class: 't' }, L(o.l))));
    }
    fs.append(box);
    if (err) fs.append(el('div', { class: 'err' }, err));
    wrap.append(fs);
    return wrap;
  }

  /* --- file --- */
  if (f.t === 'file') {
    wrap.append(el('label', { for: id }, ...labelText));
    if (f.hint) wrap.append(el('div', { class: 'hint' }, L(f.hint)));
    const file = state.files[f.k];
    const name = el('span', { class: 'name' + (file ? ' set' : '') }, file ? file.name : T('noFile'));
    const inp = el('input', { type: 'file', id, class: 'sr', accept: (ACCEPT[f.accept || 'any'] || []).join(',') });
    inp.addEventListener('change', () => { if (inp.files[0]) { state.files[f.k] = inp.files[0]; onChange(true); } });
    const row = el('div', { class: 'file' },
      el('button', { type: 'button', class: 'btn ghost small', onclick: () => inp.click() }, T('chooseFile')),
      name, inp,
      file ? el('button', { type: 'button', class: 'btn danger', onclick: () => { delete state.files[f.k]; onChange(true); } }, T('remove')) : null);
    wrap.append(row);
    if (err) wrap.append(el('div', { class: 'err' }, err));
    return wrap;
  }

  /* --- repeat --- */
  if (f.t === 'repeat') {
    const rows = Array.isArray(scope[f.k]) ? scope[f.k] : (scope[f.k] = []);
    wrap.append(el('label', {}, ...labelText));
    rows.forEach((row, i) => {
      const block = el('div', { class: 'rep' });
      block.append(el('div', { class: 'rep-head' },
        el('h3', {}, `${L(f.itemLabel)} ${i + 1}`),
        el('button', { type: 'button', class: 'btn danger', onclick: () => { rows.splice(i, 1); onChange(true); } }, T('remove'))));
      const g = el('div', { class: 'grid' });
      for (const sf of f.sub) {
        const node = renderField(sf, row, `${f.k}.${i}.${sf.k}`);
        if (node) g.append(node);
      }
      block.append(g);
      wrap.append(block);
    });
    wrap.append(el('button', { type: 'button', class: 'btn ghost small', onclick: () => { rows.push({}); onChange(true); } }, L(f.addLabel) || T('add')));
    return wrap;
  }

  /* --- select --- */
  if (f.t === 'select') {
    wrap.append(el('label', { for: id }, ...labelText));
    if (f.hint) wrap.append(el('div', { class: 'hint' }, L(f.hint)));
    const sel = el('select', { id, 'aria-invalid': err ? 'true' : null });
    sel.append(el('option', { value: '' }, T('select')));
    for (const o of optionsFor(f)) {
      const op = el('option', { value: o.v }, L(o.l));
      if (scope[f.k] === o.v) op.selected = true;
      sel.append(op);
    }
    sel.addEventListener('change', () => { scope[f.k] = sel.value; onChange(true); });
    wrap.append(sel);
    if (err) wrap.append(el('div', { class: 'err' }, err));
    return wrap;
  }

  /* --- text-like --- */
  wrap.append(el('label', { for: id }, ...labelText));
  if (f.hint) wrap.append(el('div', { class: 'hint' }, L(f.hint)));
  const tag = f.t === 'textarea' ? 'textarea' : 'input';
  const node = el(tag, {
    id, type: f.t === 'textarea' ? null : f.t,
    value: f.t === 'textarea' ? null : (scope[f.k] ?? ''),
    placeholder: f.ph || null, maxlength: f.max || null,
    min: f.t === 'number' && f.min !== undefined ? f.min : null,
    max: f.t === 'number' && f.max !== undefined ? f.max : null,
    disabled: f.ro || null, 'aria-invalid': err ? 'true' : null,
    dir: /name_arabic|badge_name_ar/.test(f.k) ? 'rtl' : (['email', 'tel', 'text', 'number'].includes(f.t) ? 'auto' : null)
  });
  if (f.t === 'textarea') node.value = scope[f.k] ?? '';
  let counter = null;
  if (f.count) { counter = el('div', { class: 'hint' }, `${(scope[f.k] || '').length} / ${f.max}`); }
  node.addEventListener('input', () => {
    scope[f.k] = node.value;
    if (counter) counter.textContent = `${node.value.length} / ${f.max}`;
    onChange(false);
  });
  node.addEventListener('blur', () => { if (state.touched) revalidateCurrent(); });
  wrap.append(node);
  if (counter) wrap.append(counter);
  if (err) wrap.append(el('div', { class: 'err' }, err));
  if (f.k === 'passport_expiry_date') { const w = passportWarning(); if (w) wrap.append(el('div', { class: 'warnbox' }, w)); }
  return wrap;
}

/* =============================================================================
   9. NAVIGATION AND SCREENS
   ============================================================================= */
const visibleSections = () => SCHEMA.filter(s => !s.showIf || s.showIf(state.data));

function onChange(rerender) {
  autofill();
  saveDraft();
  if (state.touched) state.errors = validateSection(visibleSections()[state.idx] || { fields: [] });
  if (rerender) renderForm(); else renderLedger();
}
function revalidateCurrent() {
  state.errors = validateSection(visibleSections()[state.idx]);
  renderForm();
}
function autofill() {
  const d = state.data;
  if (!d.badge_name_en && d.first_name_passport && d.family_name_passport)
    d.badge_name_en = `${d.first_name_passport} ${d.family_name_passport}`.trim();
  if (!d.timezone) { try { d.timezone = Intl.DateTimeFormat().resolvedOptions().timeZone; } catch (e) { } }
  if (!d.correspondence_language) d.correspondence_language = state.lang;
  d.presentation_language = 'en';   // sessions run in English; re-add the field to change this
}

function setLang(lang) {
  state.lang = lang;
  document.documentElement.lang = lang;
  document.documentElement.dir = lang === 'ar' ? 'rtl' : 'ltr';
  document.getElementById('langToggle').textContent = lang === 'ar' ? 'English' : 'العربية';
  document.getElementById('ledger-h').textContent = T('sections');
  renderChrome();
  render();
}

function renderChrome() {
  const ev = state.event;
  document.getElementById('ev-title').textContent = L(ev.title);
  document.getElementById('ev-org').textContent = state.lang === 'ar'
    ? 'الجهاز المركزي للمحاسبات — جمهورية مصر العربية'
    : 'Accountability State Authority — Arab Republic of Egypt';
  document.getElementById('dr-event').innerHTML = `<b>${ev.code}</b>`;
  document.getElementById('dr-dates').textContent = `${L(ev.dates)}, ${L(ev.venue)}`;
  document.getElementById('dr-status').textContent = state.lang === 'ar'
    ? 'كل تسجيل يخضع لاعتماد المكتب الفني للعلاقات الدولية'
    : 'Every registration is subject to approval by the Technical Office for International Relations';
}

function renderLedger() {
  const list = document.getElementById('ledger-list'); clear(list);
  const secs = visibleSections();
  secs.forEach((s, i) => {
    let st = 'todo';
    if (i === state.idx && state.screen === 'form') st = 'current';
    else if (i < state.idx || state.screen === 'review') st = Object.keys(validateSection(s)).length ? 'error' : 'done';
    const mark = st === 'done' ? '✓' : st === 'error' ? '!' : st === 'current' ? '●' : '';
    const li = el('li', { 'data-state': st, class: i <= state.idx ? 'clickable' : '' },
      el('span', { class: 'n' }, String(i + 1).padStart(2, '0')),
      el('span', {}, L(s.title)),
      el('span', { class: 'mk' }, mark));
    if (i <= state.idx) li.addEventListener('click', () => goTo(i));
    list.append(li);
  });
  const rv = el('li', { 'data-state': state.screen === 'review' ? 'current' : 'todo' },
    el('span', { class: 'n' }, String(secs.length + 1).padStart(2, '0')),
    el('span', {}, T('reviewTitle')), el('span', { class: 'mk' }, ''));
  list.append(rv);

  const mp = document.getElementById('mprog');
  const cur = state.screen === 'review' ? secs.length : state.idx;
  mp.querySelector('#mprog-name').textContent = state.screen === 'review' ? T('reviewTitle') : L(secs[state.idx].title);
  mp.querySelector('#mprog-count').textContent = `${T('step')} ${cur + 1} ${T('of')} ${secs.length + 1}`;
  mp.querySelector('#mprog-bar').style.width = ((cur) / secs.length * 100).toFixed(0) + '%';
}

function goTo(i) { state.idx = i; state.screen = 'form'; state.errors = {}; state.touched = false; render(); window.scrollTo(0, 0); }

function next() {
  const secs = visibleSections();
  state.touched = true;
  state.errors = validateSection(secs[state.idx]);
  if (Object.keys(state.errors).length) { renderForm(); return; }
  state.touched = false;
  if (state.idx < secs.length - 1) { state.idx++; state.screen = 'form'; }
  else state.screen = 'review';
  render(); window.scrollTo(0, 0);
}
function back() {
  if (state.screen === 'review') { state.screen = 'form'; state.idx = visibleSections().length - 1; }
  else if (state.idx > 0) state.idx--;
  state.errors = {}; state.touched = false;
  render(); window.scrollTo(0, 0);
}

/* =============================================================================
   10. API LAYER
   Replace MOCK with the deployed Worker. Contract documented in API-CONTRACT.md.
   ============================================================================= */
async function call(path, body) {
  if (CONFIG.MOCK) return mock(path, body);
  const headers = { 'Content-Type': 'application/json' };
  if (state.session) headers['Authorization'] = 'Bearer ' + state.session;
  const r = await fetch(CONFIG.apiBase + path, { method: 'POST', headers, body: JSON.stringify(body) });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || 'request_failed');
  return j;
}
function mock(path, body) {
  return new Promise((res, rej) => setTimeout(() => {
    if (path === '/invitations/verify') {
      if (!RE.code.test(body.invitation_code)) return rej(new Error('invalid_code'));
      const allowFree = CONFIG.mockFreeEmailCodes.includes(body.invitation_code);
      if (FREE_MAIL.includes(domainOf(body.email)) && !allowFree) return rej(new Error('free_email_not_allowed'));
      return res({ ok: true, organization_name: 'Office of the Auditor-General', country: 'KE',
                   allow_free_email: allowFree, otp_sent: true });
    }
    if (path === '/otp/verify') {
      return body.otp === '123456' ? res({ ok: true, session: 'mock-session' }) : rej(new Error('bad_otp'));
    }
    if (path === '/registrations') {
      return res({ ok: true, status: 'under_review', reference: 'SUB-' + Math.random().toString(36).slice(2, 8).toUpperCase() });
    }
    res({ ok: true });
  }, 500));
}

/* =============================================================================
   11. SCREENS
   ============================================================================= */
const head = (kicker, title, desc) => {
  document.getElementById('s-kicker').textContent = kicker || '';
  document.getElementById('s-title').textContent = title || '';
  document.getElementById('s-desc').textContent = desc || '';
};
const body = () => { const b = document.getElementById('s-body'); clear(b); b.setAttribute('data-anim', Date.now()); return b; };
const foot = () => { const f = document.getElementById('s-foot'); clear(f); return f; };
const showChrome = (on) => {
  document.getElementById('ledger').style.display = on ? '' : 'none';
  document.getElementById('mprog').style.display = on ? '' : 'none';
  const w = document.getElementById('wrap');
  w.style.gridTemplateColumns = on ? '' : '1fr';
  w.style.maxWidth = on ? '' : '660px';
};

/* --- Gate ------------------------------------------------------------- */
function renderGate() {
  showChrome(false);
  head(state.lang === 'ar' ? 'التحقق من الأهلية' : 'Eligibility check',
    state.lang === 'ar' ? 'ابدأ برمز الدعوة' : 'Start with your invitation code',
    state.lang === 'ar'
      ? 'التسجيل في هذا الاجتماع مقصور على المدعوين. أدخل رمز الدعوة الوارد في خطاب الدعوة الرسمي المرسل إلى جهازك، وبريد جهة عملك.'
      : 'Registration for this meeting is by invitation. Enter the code from the official invitation letter sent to your institution, together with your institutional email.');
  const b = body();
  const g = el('div', { class: 'grid' });

  const codeErr = state.errors.invitation_code, mailErr = state.errors.institutional_email;
  const code = el('input', { type: 'text', id: 'gcode', value: state.data.invitation_code || '', placeholder: 'ASA-WGITA35-KEN-7Q4M', 'aria-invalid': codeErr ? 'true' : null });
  code.addEventListener('input', () => { code.value = code.value.toUpperCase().replace(/\s/g, ''); state.data.invitation_code = code.value; });
  const mail = el('input', { type: 'email', id: 'gmail', value: state.data.institutional_email || '', 'aria-invalid': mailErr ? 'true' : null });
  mail.addEventListener('input', () => { state.data.institutional_email = mail.value.trim(); });

  g.append(
    el('div', { class: 'f wide' }, el('label', { for: 'gcode' }, state.lang === 'ar' ? 'رمز الدعوة' : 'Invitation code', el('span', { class: 'req' }, '*')),
      code, codeErr ? el('div', { class: 'err' }, codeErr) : null),
    el('div', { class: 'f wide' }, el('label', { for: 'gmail' }, state.lang === 'ar' ? 'بريد جهة العمل' : 'Institutional email', el('span', { class: 'req' }, '*')),
      el('div', { class: 'hint' }, state.lang === 'ar'
        ? 'استخدم بريد جهة عملك. تُقبل العناوين الشخصية للدعوات التي حددتها الأمانة مسبقاً فقط، ولا تُقبل العناوين المؤقتة.'
        : 'Use your institutional email. Personal addresses are accepted only on invitations the secretariat has designated, and temporary addresses are never accepted.'),
      mail, mailErr ? el('div', { class: 'err' }, mailErr) : null),
    el('input', { type: 'text', name: 'company_url', class: 'sr', tabindex: '-1', autocomplete: 'off', id: 'hp' })
  );
  b.append(g);
  b.append(el('div', { class: 'notice', style: 'margin-top:24px' },
    el('div', {}, state.lang === 'ar' ? 'قبل أن تبدأ، جهّز:' : 'Before you begin, have ready:'),
    el('ul', {},
      el('li', {}, state.lang === 'ar' ? 'جواز سفرك، فالبيانات تُدخل كما هي مطبوعة' : 'Your passport, since details are entered exactly as printed'),
      el('li', {}, state.lang === 'ar' ? 'خط سير الرحلة ورقم حجز الفندق إن وُجدا' : 'Your flight itinerary and hotel booking reference, if you have them'),
      el('li', {}, state.lang === 'ar' ? 'نسخة رقمية من الجواز إذا كنت ستطلب خطاب تأشيرة' : 'A digital copy of your passport if you will request a visa letter'))));
  if (CONFIG.MOCK) b.append(el('div', { class: 'warnbox' }, state.lang === 'ar'
    ? 'نسخة تجريبية: أي رمز بالصيغة ASA-XXXX-XX-XXXX يُقبل، ورمز التحقق هو 123456. لتجربة قبول بريد شخصي استخدم الرمز ASA-DEMO-EXP-9K4T. لا تُرسل أي بيانات إلى خادم.'
    : 'Demo build: any code shaped ASA-XXXX-XX-XXXX is accepted and the verification code is 123456. To test a personal address, use code ASA-DEMO-EXP-9K4T. Nothing is sent to a server.'));

  const btn = el('button', { class: 'btn', onclick: submitGate }, state.lang === 'ar' ? 'إرسال رمز التحقق' : 'Send verification code');
  foot().append(btn, el('span', { class: 'foot-spacer' }),
    el('span', { class: 'savenote' }, `${state.lang === 'ar' ? 'الأمانة' : 'Secretariat'}: ${CONFIG.supportEmail}`));
}

async function submitGate() {
  const e = {};
  const c = state.data.invitation_code || '', m = state.data.institutional_email || '';
  if (!c) e.invitation_code = T('errRequired'); else if (!RE.code.test(c)) e.invitation_code = T('errCode');
  if (!m) e.institutional_email = T('errRequired');
  else if (!RE.email.test(m)) e.institutional_email = T('errEmail');
  else if (DISPOSABLE.includes(domainOf(m))) e.institutional_email = T('errDisposable');
  // A personal address is not rejected here. Only the invitation record knows
  // whether one is permitted, so the decision belongs to the server.
  if (document.getElementById('hp')?.value) return;           // honeypot
  if ((Date.now() - state.startedAt) / 1000 < CONFIG.minFillSeconds && !CONFIG.MOCK) return;
  state.errors = e;
  if (Object.keys(e).length) return renderGate();
  try {
    const r = await call('/invitations/verify', { event_code: state.event.code, invitation_code: c, email: m });
    state.data.personal_email = FREE_MAIL.includes(domainOf(m));
    state.data.personal_email_permitted = !!r.allow_free_email;
    if (r.organization_name && !state.data.organization_name) state.data.organization_name = r.organization_name;
    if (r.country && !state.data.country) state.data.country = r.country;
    state.data.email = m;
    state.otpEmail = m;
    state.screen = 'otp'; state.errors = {}; render();
  } catch (err) {
    state.errors = String(err.message) === 'free_email_not_allowed'
      ? { institutional_email: T('errFreeEmail') }
      : { invitation_code: T('errCode') };
    renderGate();
  }
}

/* --- OTP -------------------------------------------------------------- */
function renderOtp() {
  showChrome(false);
  head(state.lang === 'ar' ? 'تأكيد البريد' : 'Email verification',
    state.lang === 'ar' ? 'أدخل الرمز المرسل إليك' : 'Enter the code we sent you',
    (state.lang === 'ar' ? 'أرسلنا رمزاً من ست خانات إلى ' : 'A six-digit code was sent to ') + state.otpEmail +
    (state.lang === 'ar' ? '. صلاحيته عشر دقائق.' : '. It is valid for ten minutes.'));
  const b = body();
  const err = state.errors.otp;
  const inp = el('input', { type: 'text', inputmode: 'numeric', maxlength: '6', id: 'otp', style: 'letter-spacing:.5em;font-size:22px;text-align:center;max-width:220px', 'aria-invalid': err ? 'true' : null });
  inp.addEventListener('input', () => { inp.value = inp.value.replace(/\D/g, ''); });
  b.append(el('div', { class: 'f' }, el('label', { for: 'otp' }, state.lang === 'ar' ? 'رمز التحقق' : 'Verification code'), inp,
    err ? el('div', { class: 'err' }, err) : null));
  b.append(el('button', { class: 'btn link', style: 'margin-top:16px', onclick: submitGate },
    state.lang === 'ar' ? 'إعادة إرسال الرمز' : 'Send the code again'));
  foot().append(
    el('button', { class: 'btn ghost', onclick: () => { state.screen = 'gate'; state.errors = {}; render(); } }, T('back')),
    el('button', { class: 'btn', onclick: verifyOtp }, T('next')));
}
async function verifyOtp() {
  const v = document.getElementById('otp').value;
  try {
    const r = await call('/otp/verify', { email: state.otpEmail, otp: v, event_code: state.event.code });
    state.session = r.session || '';
    loadDraft(); autofill();
    state.screen = 'form'; state.idx = 0; state.errors = {}; render(); window.scrollTo(0, 0);
  } catch (e) { state.errors = { otp: T('errOtp') }; renderOtp(); }
}

/* --- Form ------------------------------------------------------------- */
function renderForm() {
  showChrome(true);
  const secs = visibleSections();
  if (state.idx > secs.length - 1) state.idx = secs.length - 1;
  const sec = secs[state.idx];
  head(`${T('step')} ${state.idx + 1} ${T('of')} ${secs.length + 1}`, L(sec.title), L(sec.desc));
  const b = body();
  if (state.touched && Object.keys(state.errors).length) b.append(el('div', { class: 'warnbox', style: 'margin:0 0 20px;border-inline-start-color:var(--err);background:var(--err-tint);color:var(--err)' }, T('errFix')));
  const g = el('div', { class: 'grid' });
  for (const f of sec.fields) { const n = renderField(f, state.data, f.k); if (n) g.append(n); }
  b.append(g);
  const ft = foot();
  ft.append(el('button', { class: 'btn ghost', disabled: state.idx === 0, onclick: back }, T('back')));
  ft.append(el('button', { class: 'btn', onclick: next }, state.idx === secs.length - 1 ? T('reviewTitle') : T('next')));
  ft.append(el('span', { class: 'foot-spacer' }));
  ft.append(el('span', { class: 'savenote' }, store.ok ? T('draftSaved') : T('draftOff')));
  renderLedger();
}

/* --- Review ----------------------------------------------------------- */
function display(f, scope) {
  const v = scope[f.k];
  if (f.t === 'file') return state.files[f.k]?.name || null;
  if (f.t === 'check') return v ? T('yes') : T('no');
  if (v === undefined || v === null || v === '' || (Array.isArray(v) && !v.length)) return null;
  const lookup = (val) => { const o = optionsFor(f).find(x => x.v === val); return o ? L(o.l) : val; };
  if (f.t === 'multi') return v.map(lookup).join('، ');
  if (f.t === 'radio' || f.t === 'select') return lookup(v);
  return String(v);
}
function renderReview() {
  showChrome(true);
  head(`${T('step')} ${visibleSections().length + 1} ${T('of')} ${visibleSections().length + 1}`, T('reviewTitle'), T('reviewDesc'));
  const b = body();
  let bad = 0;
  visibleSections().forEach((sec, i) => {
    const errs = validateSection(sec); bad += Object.keys(errs).length;
    const box = el('div', { class: 'review-sec' });
    box.append(el('div', { class: 'rh' }, el('h3', {}, L(sec.title)),
      el('button', { class: 'btn link', onclick: () => goTo(i) }, T('edit'))));
    if (Object.keys(errs).length) box.append(el('div', { class: 'err', style: 'margin-bottom:10px' }, T('errFix')));
    const dl = el('dl', { class: 'dl' });
    for (const f of sec.fields) {
      if (!isVisible(f, state.data) || f.t === 'note') continue;
      if (f.t === 'repeat') {
        const rows = state.data[f.k] || [];
        rows.forEach((row, ri) => {
          dl.append(el('dt', {}, `${L(f.itemLabel)} ${ri + 1}`));
          dl.append(el('dd', {}, f.sub.map(sf => display(sf, row)).filter(Boolean).join(' · ') || T('notProvided')));
        });
        continue;
      }
      const val = display(f, state.data);
      dl.append(el('dt', {}, L(f.l)));
      dl.append(el('dd', { class: val ? '' : 'empty' }, val || T('notProvided')));
    }
    box.append(dl);
    b.append(box);
  });
  const ft = foot();
  ft.append(el('button', { class: 'btn ghost', onclick: back }, T('back')));
  const sub = el('button', { class: 'btn', disabled: bad > 0, onclick: () => doSubmit(sub) }, T('submit'));
  ft.append(sub);
  ft.append(el('span', { class: 'foot-spacer' }));
  if (bad) ft.append(el('span', { class: 'err' }, T('errFix')));
  renderLedger();
}

async function doSubmit(btn) {
  btn.disabled = true; btn.textContent = T('sending');
  try {
    const r = await call('/registrations', buildPayload());
    state.reference = r.reference || '';
    store.del(CONFIG.draftKey);
    state.screen = 'done'; render(); window.scrollTo(0, 0);
  } catch (e) {
    btn.disabled = false; btn.textContent = T('submit');
    const m = String(e.message) === 'session_expired' ? T('errExpired')
            : String(e.message) === 'duplicate_registration' ? T('errDuplicate') : T('netErr');
    foot().append(el('span', { class: 'err' }, m));
  }
}
function buildPayload() {
  const consents = {};
  for (const k of ['consent_processing', 'consent_visa_sharing', 'consent_hotel_sharing', 'consent_media', 'consent_delegate_list', 'consent_recording', 'declaration_accuracy'])
    if (k in state.data) consents[k] = { value: !!state.data[k], at: new Date().toISOString(), policy_version: '1.0' };
  return {
    event_code: state.event.code,
    invitation_code: state.data.invitation_code,
    locale: state.lang,
    fill_seconds: Math.round((Date.now() - state.startedAt) / 1000),
    personal_email: !!state.data.personal_email,
    personal_email_permitted: !!state.data.personal_email_permitted,
    attachments: Object.keys(state.files).map(k => ({ field: k, filename: state.files[k].name, size: state.files[k].size, mime: state.files[k].type })),
    registration: state.data,
    consents
  };
}

/* --- Done ------------------------------------------------------------- */
function renderDone() {
  showChrome(false);
  head('', state.lang === 'ar' ? 'استلمنا طلب تسجيلك' : 'Your registration has been received',
    state.lang === 'ar'
      ? 'طلبك الآن قيد المراجعة لدى المكتب الفني لرئيس الجهاز للعلاقات الدولية.'
      : 'It is now under review by the Technical Office for International Relations.');
  const b = body();
  b.append(el('div', { class: 'stamp' }, state.lang === 'ar' ? 'قيد المراجعة' : 'Under review'));
  if (state.reference) b.append(el('p', { style: 'margin-top:20px' },
    (state.lang === 'ar' ? 'الرقم المرجعي للطلب: ' : 'Your submission reference: '), el('b', {}, state.reference)));
  b.append(el('div', { class: 'notice', style: 'margin-top:20px' },
    el('div', {}, state.lang === 'ar' ? 'ما يحدث بعد ذلك:' : 'What happens next:'),
    el('ul', {},
      el('li', {}, state.lang === 'ar' ? 'تطابق الأمانة طلبك مع خطاب الترشيح الوارد من جهازك.' : 'The secretariat matches your submission against the nomination received from your institution.'),
      el('li', {}, state.lang === 'ar' ? 'عند الاعتماد يصلك رقم التسجيل ورمز QR ورابط تعديل شخصي على بريدك المسجل.' : 'On approval you receive your registration number, QR code and a personal edit link by email.'),
      el('li', {}, state.lang === 'ar' ? 'يصدر خطاب تسهيل التأشيرة، عند طلبه، خلال خمسة أيام عمل من الاعتماد.' : 'The visa facilitation letter, where requested, is issued within five working days of approval.'),
      el('li', {}, state.lang === 'ar' ? 'رقم التسجيل ورمز QR لا يصدران قبل الاعتماد.' : 'No registration number or QR code is issued before approval.'))));
  b.append(el('p', { style: 'margin-top:20px' }, (state.lang === 'ar' ? 'للاستفسار: ' : 'Questions: '), CONFIG.supportEmail));
  foot();
}

/* --- Closed ----------------------------------------------------------- */
function renderClosed() {
  showChrome(false);
  head('', T('closed'), T('closedBody'));
  body(); foot().append(el('span', { class: 'savenote' }, CONFIG.supportEmail));
}

function render() {
  ({ gate: renderGate, otp: renderOtp, form: renderForm, review: renderReview, done: renderDone, closed: renderClosed }[state.screen])();
}

/* =============================================================================
   12. INIT
   ============================================================================= */
(function init() {
  const q = new URLSearchParams(location.search);
  const code = q.get('event') || Object.keys(EVENTS)[0];
  state.event = EVENTS[code] || EVENTS[Object.keys(EVENTS)[0]];
  if (q.get('code')) state.data.invitation_code = q.get('code').toUpperCase();
  const lang = q.get('lang') === 'ar' ? 'ar' : 'en';
  document.getElementById('langToggle').addEventListener('click', () => setLang(state.lang === 'ar' ? 'en' : 'ar'));
  if (state.event.closesAt && Date.now() > new Date(state.event.closesAt).getTime()) state.screen = 'closed';
  setLang(lang);
})();
