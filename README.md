# PintOS 운영체제 구현 프로젝트

## 📌 프로젝트 개요
PintOS는 x86 아키텍처를 위한 교육용 운영체제로, 운영체제의 핵심 개념을 실제로 구현해보며 이해할 수 있는 프로젝트입니다.

## ⏱️ 개발 기간
2024.08.22 - 2024.10.02 (5주)

## 💻 개발 환경
- Language: C
- Architecture: 80x86
- Environment: Ubuntu 18.04 LTS
- Tools: GDB, QEMU

## 🔍 주요 구현 내용

### Thread 
- 우선순위 기반 스케줄러 구현
- Priority Donation을 통한 Priority Inversion 문제 해결
- Multi-level Feedback Queue 구현으로 CPU 자원 공정 분배

### User Program
- System Call 인터페이스 구현
- 프로세스 관리 시스템 구축
- File Descriptor 관리 시스템 개발

### Virtual Memory
- Page Table Management 구현
- Stack Growth 동적 관리
- Memory Mapped Files 지원
- Swap In/Out 매커니즘 구현

## 🏆 주요 기술 성과

### 시스템 안정성 검증
- Thread (27/27), User Program (95/95), VM (134/141) 테스트케이스 97% 통과
- 복잡한 시나리오에서의 시스템 견고성 입증

### 스레드 관리 최적화
- Priority Donation 알고리즘 구현으로 Priority Inversion 문제 해결
- 효율적인 Thread 대기열 시스템 구축
  - Busy Waiting 제거로 CPU 리소스 절약
  - 스레드간 동기화 신뢰성 향상
  - Race Condition 방지 메커니즘 구현

### 메모리 관리 시스템 구축
- 프로세스 생명주기 관리 시스템 구현
  - 부모 프로세스 종료 시 자식 프로세스 정리
  - 고아 프로세스 자동 정리 메커니즘
  - 좀비 프로세스 방지 시스템
- 체계적인 메모리 누수 방지
  - 자원 할당/해제 추적 시스템
  - 메모리 참조 카운팅 구현
  - 순환 참조 감지 및 처리

