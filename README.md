[![test](https://github.com/maxirmx/dkg/actions/workflows/test.yml/badge.svg)](https://github.com/maxirmx/dkg/actions/workflows/test.yml)
[![CodeQL](https://github.com/maxirmx/dkg/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/maxirmx/dkg/actions/workflows/github-code-scanning/codeql)

# Dkg
Implementation in C# of a distributed key generation algorithm (Pedersen 91) with a K-of-N threshold scheme (Shamir scheme) on standard elliptic curves (Sec256k1 with an option to replace)

Реализация на c# алгоритма распределённой генерации ключей (Pedersen 91) с пороговой схемой K из N (схема Шамира) на стандартных эллиптических кривых (Sec256k1 c возможностью замены)

## Theoretical basis/Теоретическая основа
- Pedersen, T.P. (1991). A Threshold Cryptosystem without a Trusted Party. In: Davies, D.W. (eds) Advances in Cryptology — EUROCRYPT ’91. EUROCRYPT 1991. Lecture Notes in Computer Science, vol 547. Springer, Berlin, Heidelberg.

  https://doi.org/10.1007/3-540-46416-6_47
- Pedersen, T.P. (1992). Non-Interactive and Information-Theoretic Secure Verifiable Secret Sharing. In: Feigenbaum, J. (eds) Advances in Cryptology — CRYPTO ’91. CRYPTO 1991. Lecture Notes in Computer Science, vol 576. Springer, Berlin, Heidelberg.

  https://doi.org/10.1007/3-540-46766-1_9
- Wong, Theodore & Wing, Jeannette. (2001). Verifiable Secret Redistribution. 

These articles are available at ```docs``` folder.
Перечисленные статьи доступны в папке ```doc```.

## Practical basis/Практическая основа
This development is the result of translation into C# and subsequent refactoring of the implementation of the above algorithms in the library [dedis](https://github.com/dedis/kyber)

Данная разработка - результат перевода на C# и последующего рефакторинга реализации вышеперечисленных алгоритмов в библиотеке [dedis](https://github.com/dedis/kyber)

## Solution structure/Структура решения

The C# solution includes three projects:
- ```dkgLibrary``` - a .net class library with implementation of algorithms and some additional utilities.
- ```dkgLibraryTests``` -- tests for dkgLibrary
- ```dkgSample``` -- demo application


С# solution включает три проекта:
- ```dkgLibrary``` -- .net class library с реализацией алгоритмов и некоторых дополнительных утилит
- ```dkgLibraryTests``` -- тесты для dkgLibrary
- ```dkgSample``` -- демонстрационное приложение

## Where to start/С чего начинать
- ```dkgLibraryTests/AnEndToEndExample.cs``` -- This test demonstrates the basic capabilities of the distributed key generation algorithm and Shamir's scheme in a synchronous form (the algorithm proposed by Pederson is synchronous in nature).
- ```dkgSample/Program.cs``` - asynchronous (multithreaded) implementation of the distributed key generation algorithm and the Shamir scheme in the gRPC server. This application does not solve the issue of node synchronization; time delays are used.

- ```dkgLibraryTests/AnEndToEndExample.cs``` -- этот тест демонстрирует основные возможности алгоритма распределённой генерации ключей и схемы Шамира в синхронном виде (алгоритм, предложенный Pederson'ом по свой природе являеся синхронным).
- ```dkgSample/Program.cs``` -- асинхронная (многопоточная) реализация алгоритма распределённой генерации ключей и схемы Шамира в видк gRPC сервера. Задача синхронизации узлов в этом приложении не решалась, испльзуются временные задержки.

## Continuation project ... / Продолжение ...
https://github.com/maxirmx/dkg-nodes

## Project financing
Initial development of this project was financed by [NarayanaSupramati](https://www.github.com/NarayanaSupramati)
