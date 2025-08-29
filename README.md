# Android ePassport Reader (JMRTD-Lite)
[![](https://jitpack.io/v/juncaffe/android-epassport-reader.svg)](https://jitpack.io/#juncaffe/android-epassport-reader)

안드로이드에서 전자여권(NFC) 칩을 읽기 위한 JMRTD 의 경량화 및 메모리보안 프로젝트입니다.

## 설치 방법 (JitPack)
이 라이브러리는 [JitPack](https://jitpack.io/#juncaffe/android-epassport-reader)을 통해 설치할 수 있습니다.

### Gradle (Kotlin DSL)
```kotlin
repositories {
    maven(url = "https://jitpack.io")
}

dependencies {
    implementation("com.github.juncaffe:android-epassport-reader:v0.0.10")
}
```

## Third-Party Notices
### JMRTD
- 원저장소: https://sourceforge.net/projects/jmrtd/
- 저작권: Copyright (c) 2006-2015 The JMRTD team
- 라이선스: GNU LGPL v2.1 (LICENSE.LGPL-2.1 참조)

변경 사항:
- 안드로이드 환경에 맞게 경량화
- SCUBA smartcard 의존성 제거
- 일부 Kotlin 변환 및 메모리 보안 고려 수정
- TD3 여권에서 다음 기능만 지원
   - DG1, DG2, DG14 
   - BAC (Basic Access Control)
   - PACE (Password Authenticated Connection Establishment)
   - CA (Chip Authentication, EAC-CA)
   - PA (Passive Authentication)
- 지원하지 않는 기능
   - TA (Terminal Authentication, EAC-TA)
   - DG3, DG4(한국 여권에는 없음) 생체정보 데이터 접근

### SCUBA (Smartcard)
- 원저장소: https://sourceforge.net/projects/scuba/
- 저작권: Copyright (c) SCUBA contributors
- 라이선스: GNU LGPL v2.1 (LICENSE.LGPL-2.1 참조)

변경 사항:
- JMRTD-lite 용 필요한 클래스만 포함
- 일부 Kotlin 변환 및 메모리 보안 고려 수정

### Bouncy Castle
- 원저장소: https://github.com/bcgit/bc-java
- 저작권: Copyright (c) 2000-2025 The Legion of the Bouncy Castle Inc
- 라이선스: MIT-Style (LICENSE.BouncyCastle 참조)
