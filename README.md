[![test](https://github.com/maxirmx/dkg/actions/workflows/test.yml/badge.svg)](https://github.com/maxirmx/dkg/actions/workflows/test.yml)
[![CodeQL](https://github.com/maxirmx/dkg/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/maxirmx/dkg/actions/workflows/github-code-scanning/codeql)

# Проект dkg

Реализация на c# алгоритма распределённой генерации ключей (Pedersen 91) с пороговой схемой K из N (схема Шамира) на стандартных эллиптических кривых (Sec256k1 c возможностью замены)

## Теоретическая основа
- Pedersen, T.P. (1991). A Threshold Cryptosystem without a Trusted Party. In: Davies, D.W. (eds) Advances in Cryptology — EUROCRYPT ’91. EUROCRYPT 1991. Lecture Notes in Computer Science, vol 547. Springer, Berlin, Heidelberg.

  https://doi.org/10.1007/3-540-46416-6_47
- Pedersen, T.P. (1992). Non-Interactive and Information-Theoretic Secure Verifiable Secret Sharing. In: Feigenbaum, J. (eds) Advances in Cryptology — CRYPTO ’91. CRYPTO 1991. Lecture Notes in Computer Science, vol 576. Springer, Berlin, Heidelberg.

  https://doi.org/10.1007/3-540-46766-1_9
- T. M. Wong, C. Wang, and J. M. Wing. Verifiable secret redistribution for archive systems. In Security in Storage Workshop, 2002. Proceedings. First International IEEE, pages 94--105. IEEE, 2002. 

Перечисленные статьи доступны в папке doc

## Практическая основа
Данный проект - результат перевода на C# и глубокой переработки реализации указанных алгоритмов в библиотеке [dedis](https://github.com/dedis/kyber)
