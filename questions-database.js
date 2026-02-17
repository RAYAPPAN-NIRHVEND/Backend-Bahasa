// ============================================================================
// QUESTION DATABASE - Real Content untuk 7 Bahasa
// File: questions-database.js
// ============================================================================

const questionsDB = {
    // ========================================================================
    // ENGLISH (Inggris)
    // ========================================================================
    english: {
        beginner: [
            // Level 1-10: Greetings & Basic Phrases
            {
                level: 1,
                type: 'multiple_choice',
                question: 'How do you greet someone in the morning?',
                correctAnswer: 'Good morning',
                options: ['Good night', 'Good morning', 'Good afternoon', 'Goodbye'],
                explanation: '"Good morning" digunakan untuk menyapa di pagi hari (sebelum jam 12 siang)',
                audio: '/audio/en/good-morning.mp3'
            },
            {
                level: 2,
                type: 'multiple_choice',
                question: 'What does "Thank you" mean?',
                correctAnswer: 'Terima kasih',
                options: ['Permisi', 'Terima kasih', 'Maaf', 'Sama-sama'],
                explanation: '"Thank you" adalah ungkapan terima kasih dalam bahasa Inggris'
            },
            {
                level: 3,
                type: 'fill_blank',
                question: 'Complete the greeting: "Nice to ____ you!"',
                correctAnswer: 'meet',
                options: ['meet', 'see', 'know', 'like'],
                explanation: '"Nice to meet you" digunakan saat bertemu seseorang untuk pertama kali'
            },
            {
                level: 4,
                type: 'translation',
                question: 'Translate to English: "Sampai jumpa"',
                correctAnswer: 'See you later',
                options: ['Hello', 'See you later', 'Thank you', 'Welcome'],
                explanation: '"See you later" atau "Goodbye" untuk mengucapkan selamat tinggal'
            },
            {
                level: 5,
                type: 'bonus',
                question: 'BONUS: Match the greetings! (Cocokkan 5 pasang)',
                correctAnswer: '5',
                options: ['3', '4', '5', '6'],
                minigame: 'matching',
                pairs: [
                    { en: 'Hello', id: 'Halo' },
                    { en: 'Goodbye', id: 'Selamat tinggal' },
                    { en: 'Please', id: 'Tolong' },
                    { en: 'Sorry', id: 'Maaf' },
                    { en: 'Thank you', id: 'Terima kasih' }
                ]
            },
            
            // Level 6-20: Numbers, Colors, Days
            {
                level: 6,
                type: 'multiple_choice',
                question: 'What number comes after "nineteen"?',
                correctAnswer: 'twenty',
                options: ['eighteen', 'twenty', 'twenty-one', 'thirty'],
                explanation: 'Urutan: nineteen (19), twenty (20), twenty-one (21)'
            },
            {
                level: 7,
                type: 'multiple_choice',
                question: 'What color is the sky on a clear day?',
                correctAnswer: 'Blue',
                options: ['Red', 'Blue', 'Green', 'Yellow'],
                explanation: 'The sky is blue (Langit berwarna biru)',
                image: '/images/sky.jpg'
            },
            {
                level: 8,
                type: 'translation',
                question: 'What day comes after Monday?',
                correctAnswer: 'Tuesday',
                options: ['Sunday', 'Tuesday', 'Wednesday', 'Thursday'],
                explanation: 'Days: Monday, Tuesday, Wednesday, Thursday, Friday, Saturday, Sunday'
            },
            {
                level: 9,
                type: 'listening',
                question: 'Listen and choose the correct number:',
                correctAnswer: 'Forty-five',
                options: ['Forty-four', 'Forty-five', 'Forty-six', 'Fifty-five'],
                audio: '/audio/en/45.mp3'
            },
            {
                level: 10,
                type: 'bonus',
                question: 'BONUS: Type the numbers 1-10 in order!',
                correctAnswer: 'one,two,three,four,five,six,seven,eight,nine,ten',
                minigame: 'typing_speed'
            }
        ],
        
        intermediate: [
            // Level 1-10: Grammar - Present Tense
            {
                level: 1,
                type: 'fill_blank',
                question: 'I ____ to school every day.',
                correctAnswer: 'go',
                options: ['go', 'goes', 'going', 'went'],
                explanation: 'Gunakan "go" untuk subject I/You/We/They. Gunakan "goes" untuk He/She/It'
            },
            {
                level: 2,
                type: 'fill_blank',
                question: 'She ____ her homework right now.',
                correctAnswer: 'is doing',
                options: ['do', 'does', 'is doing', 'did'],
                explanation: 'Present Continuous (sedang berlangsung): Subject + is/am/are + verb-ing'
            },
            {
                level: 3,
                type: 'multiple_choice',
                question: 'Choose the correct sentence:',
                correctAnswer: 'He plays football every weekend.',
                options: [
                    'He play football every weekend.',
                    'He plays football every weekend.',
                    'He playing football every weekend.',
                    'He is play football every weekend.'
                ],
                explanation: 'Untuk He/She/It, tambahkan -s/-es di akhir verb: play → plays'
            },
            {
                level: 4,
                type: 'error_detection',
                question: 'Find the mistake: "They is going to the mall."',
                correctAnswer: 'is → are',
                options: ['They → Their', 'is → are', 'going → go', 'No mistake'],
                explanation: 'They (plural) + are. He/She/It (singular) + is'
            },
            {
                level: 5,
                type: 'bonus',
                question: 'BONUS: Arrange the words to form a correct sentence!',
                correctAnswer: 'She reads books every night.',
                minigame: 'word_arrangement',
                words: ['She', 'reads', 'books', 'every', 'night', '.']
            }
        ],
        
        advanced: [
            // Level 1-10: Idioms & Advanced Grammar
            {
                level: 1,
                type: 'multiple_choice',
                question: 'What does "break the ice" mean?',
                correctAnswer: 'Start a conversation in a social situation',
                options: [
                    'Break something made of ice',
                    'Start a conversation in a social situation',
                    'Feel very cold',
                    'Stop talking to someone'
                ],
                explanation: '"Break the ice" = memulai percakapan untuk menghilangkan kecanggungan'
            },
            {
                level: 2,
                type: 'idiom',
                question: '"It\'s raining cats and dogs" means:',
                correctAnswer: 'It is raining very heavily',
                options: [
                    'Animals are falling from the sky',
                    'It is raining very heavily',
                    'The weather is nice',
                    'There are many pets outside'
                ],
                explanation: 'Idiom untuk mengatakan hujan sangat deras'
            },
            {
                level: 3,
                type: 'context',
                question: 'In a business meeting, your colleague says "Let\'s touch base next week." This means:',
                correctAnswer: 'Let\'s talk or meet again next week',
                options: [
                    'Let\'s physically touch something',
                    'Let\'s talk or meet again next week',
                    'Let\'s work at a base',
                    'Let\'s finish the project next week'
                ],
                explanation: '"Touch base" = berkomunikasi atau bertemu secara singkat untuk update'
            }
        ]
    },

    // ========================================================================
    // JAPANESE (日本語)
    // ========================================================================
    japanese: {
        beginner: [
            {
                level: 1,
                type: 'multiple_choice',
                question: 'Apa arti "こんにちは" (Konnichiwa)?',
                correctAnswer: 'Selamat siang / Halo',
                options: ['Selamat pagi', 'Selamat siang / Halo', 'Selamat malam', 'Terima kasih'],
                explanation: 'こんにちは (Konnichiwa) digunakan untuk menyapa di siang hari',
                hiragana: 'こんにちは',
                romaji: 'Konnichiwa'
            },
            {
                level: 2,
                type: 'multiple_choice',
                question: 'Bagaimana cara mengucapkan "Terima kasih" dalam bahasa Jepang?',
                correctAnswer: 'ありがとう (Arigatou)',
                options: [
                    'すみません (Sumimasen)',
                    'ありがとう (Arigatou)',
                    'さようなら (Sayounara)',
                    'おはよう (Ohayou)'
                ],
                explanation: 'ありがとう (Arigatou) = Terima kasih. Formal: ありがとうございます (Arigatou gozaimasu)',
                hiragana: 'ありがとう',
                romaji: 'Arigatou'
            },
            {
                level: 3,
                type: 'hiragana_recognition',
                question: 'Pilih Hiragana yang benar untuk "A"',
                correctAnswer: 'あ',
                options: ['あ', 'い', 'う', 'え'],
                explanation: 'Hiragana: あ (a), い (i), う (u), え (e), お (o)',
                study_tip: 'Ini adalah 5 vokal dasar dalam bahasa Jepang'
            },
            {
                level: 4,
                type: 'multiple_choice',
                question: 'Bagaimana cara mengatakan "Saya" dalam bahasa Jepang?',
                correctAnswer: 'わたし (Watashi)',
                options: [
                    'わたし (Watashi)',
                    'あなた (Anata)',
                    'かれ (Kare)',
                    'かのじょ (Kanojo)'
                ],
                explanation: 'わたし (Watashi) = Saya. あなた (Anata) = Kamu. かれ (Kare) = Dia (laki-laki)',
                hiragana: 'わたし',
                romaji: 'Watashi'
            },
            {
                level: 5,
                type: 'bonus',
                question: 'BONUS: Cocokkan Hiragana dengan Romaji!',
                correctAnswer: '10',
                minigame: 'matching',
                pairs: [
                    { jp: 'あ', romaji: 'a' },
                    { jp: 'い', romaji: 'i' },
                    { jp: 'う', romaji: 'u' },
                    { jp: 'え', romaji: 'e' },
                    { jp: 'お', romaji: 'o' },
                    { jp: 'か', romaji: 'ka' },
                    { jp: 'き', romaji: 'ki' },
                    { jp: 'く', romaji: 'ku' },
                    { jp: 'け', romaji: 'ke' },
                    { jp: 'こ', romaji: 'ko' }
                ]
            },
            {
                level: 6,
                type: 'kanji_reading',
                question: 'Apa bacaan Kanji ini: 日本',
                correctAnswer: 'にほん (Nihon)',
                options: [
                    'にほん (Nihon)',
                    'ちゅうごく (Chuugoku)',
                    'かんこく (Kankoku)',
                    'あめりか (Amerika)'
                ],
                explanation: '日本 (Nihon/Nippon) = Jepang. 日 = sun/day, 本 = origin/book',
                kanji: '日本',
                meaning: 'Jepang (Land of the Rising Sun)'
            },
            {
                level: 7,
                type: 'counting',
                question: 'Bagaimana menghitung "1, 2, 3" dalam bahasa Jepang?',
                correctAnswer: 'いち、に、さん (Ichi, Ni, San)',
                options: [
                    'いち、に、さん (Ichi, Ni, San)',
                    'ひとつ、ふたつ、みっつ (Hitotsu, Futatsu, Mittsu)',
                    'いち、いち、いち (Ichi, Ichi, Ichi)',
                    'さん、に、いち (San, Ni, Ichi)'
                ],
                explanation: 'Angka Sino-Japanese: 1=いち(ichi), 2=に(ni), 3=さん(san), 4=し/よん(shi/yon), 5=ご(go)'
            }
        ],
        
        intermediate: [
            {
                level: 1,
                type: 'particle',
                question: 'Pilih partikel yang benar: わたし ___ がくせいです (Saya adalah pelajar)',
                correctAnswer: 'は',
                options: ['は', 'が', 'を', 'に'],
                explanation: 'は (wa) adalah topic marker. Pattern: [Noun] は [Noun] です',
                sentence: 'わたしはがくせいです',
                romaji: 'Watashi wa gakusei desu'
            },
            {
                level: 2,
                type: 'verb_conjugation',
                question: 'Bentuk masu dari たべる (taberu - makan) adalah:',
                correctAnswer: 'たべます (tabemasu)',
                options: [
                    'たべます (tabemasu)',
                    'たべました (tabemashita)',
                    'たべない (tabenai)',
                    'たべて (tabete)'
                ],
                explanation: 'Verb-masu form (polite): たべる → たべます. Past: たべました'
            }
        ],
        
        advanced: [
            {
                level: 1,
                type: 'keigo',
                question: 'Pilih bentuk keigo (sopan) yang tepat: "Makan" → "Dimakan (oleh orang terhormat)"',
                correctAnswer: 'めしあがる (meshiagaru)',
                options: [
                    'たべる (taberu)',
                    'めしあがる (meshiagaru)',
                    'いただく (itadaku)',
                    'たべます (tabemasu)'
                ],
                explanation: 'めしあがる adalah sonkeigo (hormat tinggi) untuk "makan". いただく adalah kenjougo (merendah)'
            }
        ]
    },

    // ========================================================================
    // GERMAN (Deutsch)
    // ========================================================================
    german: {
        beginner: [
            {
                level: 1,
                type: 'multiple_choice',
                question: 'Wie sagt man "Guten Morgen" auf Indonesisch?',
                correctAnswer: 'Selamat pagi',
                options: ['Selamat siang', 'Selamat pagi', 'Selamat malam', 'Terima kasih'],
                explanation: '"Guten Morgen" = Selamat pagi (digunakan sebelum jam 10-11 pagi)',
                pronunciation: 'GOO-ten MOR-gen'
            },
            {
                level: 2,
                type: 'article',
                question: 'Artikel yang tepat untuk "Tisch" (meja) adalah:',
                correctAnswer: 'der',
                options: ['der', 'die', 'das', 'den'],
                explanation: 'der Tisch (masculine). die = feminine, das = neuter',
                gender_tip: 'Tisch adalah maskulin karena kebanyakan benda perabot maskulin'
            },
            {
                level: 3,
                type: 'translation',
                question: 'Wie heißt du?',
                correctAnswer: 'Siapa namamu?',
                options: ['Apa kabar?', 'Siapa namamu?', 'Berapa umurmu?', 'Dari mana asalmu?'],
                explanation: '"Wie heißt du?" = Siapa namamu? (informal). Formal: "Wie heißen Sie?"',
                pronunciation: 'vee HEISST doo'
            }
        ],
        
        intermediate: [
            {
                level: 1,
                type: 'case',
                question: 'Kalimat mana yang menggunakan Akkusativ case yang benar?',
                correctAnswer: 'Ich sehe den Mann',
                options: [
                    'Ich sehe der Mann',
                    'Ich sehe den Mann',
                    'Ich sehe dem Mann',
                    'Ich sehe des Mannes'
                ],
                explanation: 'Akkusativ case untuk direct object. der → den (maskulin)',
                case_tip: 'Nominativ: der/die/das. Akkusativ: den/die/das'
            }
        ],
        
        advanced: [
            {
                level: 1,
                type: 'idiom',
                question: 'Was bedeutet "Das ist nicht mein Bier"?',
                correctAnswer: 'Itu bukan urusanku',
                options: [
                    'Itu bukan birku',
                    'Itu bukan urusanku',
                    'Saya tidak suka bir',
                    'Bir itu tidak enak'
                ],
                explanation: 'Idiom Jerman untuk "That\'s not my business / None of my concern"'
            }
        ]
    },

    // ========================================================================
    // DUTCH (Nederlands)
    // ========================================================================
    dutch: {
        beginner: [
            {
                level: 1,
                type: 'multiple_choice',
                question: 'Hoe zeg je "Hallo" in het Nederlands?',
                correctAnswer: 'Hallo / Hoi',
                options: ['Goedemorgen', 'Hallo / Hoi', 'Tot ziens', 'Dank je'],
                explanation: '"Hallo" atau "Hoi" untuk sapaan informal. "Goedemorgen" = Selamat pagi',
                pronunciation: 'HAH-lo / HOY'
            },
            {
                level: 2,
                type: 'translation',
                question: 'Wat betekent "Ik ben student"?',
                correctAnswer: 'Saya adalah mahasiswa',
                options: [
                    'Saya adalah guru',
                    'Saya adalah mahasiswa',
                    'Saya adalah dokter',
                    'Saya suka belajar'
                ],
                explanation: '"Ik ben" = Saya adalah. "student" = mahasiswa/pelajar',
                pronunciation: 'ik ben stew-DENT'
            }
        ],
        
        intermediate: [
            {
                level: 1,
                type: 'word_order',
                question: 'Susun kata-kata ini dengan benar: "gisteren / ik / naar / ging / school"',
                correctAnswer: 'Ik ging gisteren naar school',
                options: [
                    'Ik ging gisteren naar school',
                    'Gisteren ik ging naar school',
                    'Ik naar school ging gisteren',
                    'School ging ik gisteren naar'
                ],
                explanation: 'Dutch word order: Subject + Verb + Time + Place. Past tense: ging (pergi)'
            }
        ]
    },

    // ========================================================================
    // HINDI (हिन्दी)
    // ========================================================================
    hindi: {
        beginner: [
            {
                level: 1,
                type: 'multiple_choice',
                question: '"नमस्ते" (Namaste) का अर्थ क्या है?',
                correctAnswer: 'Halo / Selamat datang',
                options: ['Terima kasih', 'Halo / Selamat datang', 'Sampai jumpa', 'Maaf'],
                explanation: 'नमस्ते (Namaste) adalah sapaan umum dalam bahasa Hindi',
                devanagari: 'नमस्ते',
                pronunciation: 'na-mas-TAY',
                cultural_note: 'Biasanya disertai dengan gesture menyatukan telapak tangan di depan dada'
            },
            {
                level: 2,
                type: 'devanagari',
                question: 'Devanagari untuk vokal "A" adalah:',
                correctAnswer: 'अ',
                options: ['अ', 'आ', 'इ', 'उ'],
                explanation: 'Vokal dasar: अ (a), आ (aa), इ (i), ई (ii), उ (u), ऊ (uu)',
                script: 'Devanagari'
            }
        ],
        
        intermediate: [
            {
                level: 1,
                type: 'verb_conjugation',
                question: 'मैं खाता हूँ (Main khaata hoon) - Bentuk untuk "She eats":',
                correctAnswer: 'वह खाती है (Vah khaatii hai)',
                options: [
                    'वह खाता है (Vah khaata hai)',
                    'वह खाती है (Vah khaatii hai)',
                    'तुम खाते हो (Tum khaate ho)',
                    'हम खाते हैं (Ham khaate hain)'
                ],
                explanation: 'Verb berubah sesuai gender dan number. Feminine singular: खाती है'
            }
        ]
    },

    // ========================================================================
    // MANDARIN (中文)
    // ========================================================================
    mandarin: {
        beginner: [
            {
                level: 1,
                type: 'multiple_choice',
                question: '你好 (Nǐ hǎo) 是什么意思？',
                correctAnswer: 'Halo',
                options: ['Terima kasih', 'Halo', 'Sampai jumpa', 'Selamat pagi'],
                explanation: '你好 (Nǐ hǎo) adalah sapaan umum dalam bahasa Mandarin',
                hanzi: '你好',
                pinyin: 'Nǐ hǎo',
                tone: '3rd tone + 3rd tone'
            },
            {
                level: 2,
                type: 'pinyin',
                question: 'Pinyin yang benar untuk 中国 (China) adalah:',
                correctAnswer: 'Zhōngguó',
                options: ['Chongkuo', 'Zhōngguó', 'Jungkuo', 'Zonggo'],
                explanation: '中 (zhōng) = tengah/pusat, 国 (guó) = negara. China = Negara Tengah',
                hanzi: '中国',
                pinyin: 'Zhōngguó'
            },
            {
                level: 3,
                type: 'tone_practice',
                question: 'Dengarkan dan pilih tone yang benar untuk "妈" (ibu):',
                correctAnswer: '1st tone (mā)',
                options: ['1st tone (mā)', '2nd tone (má)', '3rd tone (mǎ)', '4th tone (mà)'],
                explanation: '妈 (mā) = ibu (1st tone). 马 (mǎ) = kuda (3rd tone)',
                audio: '/audio/zh/ma1.mp3'
            }
        ],
        
        intermediate: [
            {
                level: 1,
                type: 'sentence_structure',
                question: 'Susun kalimat: "我 / 学习 / 中文 / 在 / 每天"',
                correctAnswer: '我每天学习中文 (Wǒ měitiān xuéxí Zhōngwén)',
                options: [
                    '我每天学习中文',
                    '每天我学习中文',
                    '学习中文我每天',
                    '中文学习我每天'
                ],
                explanation: 'Pattern: Subject + Time + Verb + Object. 我每天学习中文 = Saya setiap hari belajar bahasa Mandarin'
            }
        ]
    },

    // ========================================================================
    // INDONESIAN (Bahasa Indonesia)
    // ========================================================================
    indonesian: {
        beginner: [
            {
                level: 1,
                type: 'multiple_choice',
                question: 'Kata yang tepat untuk sapaan pagi hari adalah:',
                correctAnswer: 'Selamat pagi',
                options: ['Selamat siang', 'Selamat pagi', 'Selamat malam', 'Halo'],
                explanation: 'Selamat pagi digunakan dari subuh hingga sekitar jam 11 siang'
            },
            {
                level: 2,
                type: 'affixes',
                question: 'Kata dasar dari "membaca" adalah:',
                correctAnswer: 'baca',
                options: ['mem', 'baca', 'membaca', 'bacaan'],
                explanation: 'Awalan me- + baca = membaca. Kata dasarnya adalah "baca"'
            },
            {
                level: 3,
                type: 'formal_informal',
                question: 'Bentuk formal dari "Gimana kabarnya?" adalah:',
                correctAnswer: 'Bagaimana kabar Anda?',
                options: [
                    'Bagaimana kabar Anda?',
                    'Gimana kabarnya?',
                    'Apa kabar lo?',
                    'Lu baik-baik aja kan?'
                ],
                explanation: 'Bahasa formal menggunakan kata baku: Bagaimana, Anda, dll'
            }
        ],
        
        intermediate: [
            {
                level: 1,
                type: 'imbuhan',
                question: 'Imbuhan yang tepat: "Saya ingin ____ pakaian ini"',
                correctAnswer: 'membeli',
                options: ['beli', 'membeli', 'terbeli', 'pembelian'],
                explanation: 'me- (awalan aktif) + beli = membeli. Pattern: Subjek + me-[kata kerja] + objek'
            }
        ]
    }
};

// ============================================================================
// QUESTION GENERATOR - Generate 100 levels per difficulty
// ============================================================================

function generateAllQuestions(language, difficulty) {
    const baseQuestions = questionsDB[language][difficulty];
    const allQuestions = [];
    
    for (let level = 1; level <= 100; level++) {
        // Use base questions and modify them progressively
        const baseIndex = (level - 1) % baseQuestions.length;
        const baseQuestion = baseQuestions[baseIndex];
        
        // Clone and modify
        const question = {
            ...baseQuestion,
            level: level,
            difficulty: Math.min(10, Math.floor(level / 10) + 1),
            timer: Math.max(10, 25 - Math.floor(level / 20))
        };
        
        // Every 5th level is bonus
        if (level % 5 === 0) {
            question.type = 'bonus';
        }
        
        allQuestions.push(question);
    }
    
    return allQuestions;
}

// ============================================================================
// API ENDPOINT
// ============================================================================

function getQuestion(language, difficulty, level) {
    const questions = generateAllQuestions(language, difficulty);
    return questions[level - 1] || questions[0];
}

module.exports = {
    questionsDB,
    generateAllQuestions,
    getQuestion
};
