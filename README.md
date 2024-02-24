[![test](https://github.com/maxirmx/dkg/actions/workflows/test.yml/badge.svg)](https://github.com/maxirmx/dkg/actions/workflows/test.yml)
[![CodeQL](https://github.com/maxirmx/dkg/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/maxirmx/dkg/actions/workflows/github-code-scanning/codeql)

# Dkg

Реализация на c# алгоритма распределённой генерации ключей (Pedersen 91) с пороговой схемой K из N (схема Шамира) на стандартных эллиптических кривых (Sec256k1 c возможностью замены)

## Теоретическая основа
- Pedersen, T.P. (1991). A Threshold Cryptosystem without a Trusted Party. In: Davies, D.W. (eds) Advances in Cryptology — EUROCRYPT ’91. EUROCRYPT 1991. Lecture Notes in Computer Science, vol 547. Springer, Berlin, Heidelberg.

  https://doi.org/10.1007/3-540-46416-6_47
- Pedersen, T.P. (1992). Non-Interactive and Information-Theoretic Secure Verifiable Secret Sharing. In: Feigenbaum, J. (eds) Advances in Cryptology — CRYPTO ’91. CRYPTO 1991. Lecture Notes in Computer Science, vol 576. Springer, Berlin, Heidelberg.

  https://doi.org/10.1007/3-540-46766-1_9
- Wong, Theodore & Wing, Jeannette. (2001). Verifiable Secret Redistribution. 

Перечисленные статьи доступны в папке doc

## Практическая основа
Данная разработка - результат перевода на C# и последующего рефакторинга реализации вышеперечисленных алгоритмов в библиотеке [dedis](https://github.com/dedis/kyber)

## Структура решения
С# solution включает три проекта:
- ```dkgLibrary``` -- .net class library с реализацией алгоритмов и некоторых дополнительных утилит
- ```dkgLibraryTests``` -- тесты для dkgLibrary
- ```dkgSample``` -- демонстрационное приложение

## С чего начинать
- ```dkgLibraryTests/AnEndToEndExample.cs``` -- этот тест демонстрирует основные возможности алгоритма распределённой генерации ключей и схемы Шамира в синхронном виде (алгоритм, предложенный Pederson'ом по свой природе являеся синхронным).
- ```dkgSample/Program.cs``` -- асинхронная (многопоточная) реализация алгоритма распределённой генерации ключей и схемы Шамира в видк gRPC сервера. Задача синхронизации узлов в этом приложении не решалась, испльзуются временные задержки.
