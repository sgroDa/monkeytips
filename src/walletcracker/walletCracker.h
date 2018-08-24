// Copyright (c) 2018, Zpalm
// GNU GPL V3

#include <tuple>
#include <Wallet/WalletGreen.h>

struct Comp
{
    /* Order by length, then by ordering */
    bool operator()(const std::string& lhs, const std::string &rhs) const
    {
        auto lhsSize = lhs.size();
        auto rhsSize = rhs.size();

        if (lhsSize == rhsSize)
        {
            return lhs < rhs;
        }

        return lhsSize < rhsSize;
    }
};

struct CrackInfo
{
    CrackInfo(CryptoNote::WalletGreen &wallet, std::string filename) :
              wallet(wallet), filename(filename) {}

    /* The wallet instance */
    CryptoNote::WalletGreen &wallet;

    /* The wallet location */
    std::string filename;

    /* Passwords we've hashed and will save to a file */
    std::map<std::string, Crypto::chacha8_key, Comp> prehashed;

    /* The character set to use whilst cracking */
    std::string alphabet;

    /* The actual password string */
    std::string correctPassword;

    /* Have we found the password */
    bool found = false;

    /* The length of passwords to resume at after trying the prehashed
       passwords */
    int passwordResumeLength = 1;
};

const int MAX_PASSWORD_LEN = 100;

void crack(CryptoNote::WalletGreen &wallet);

void outputPassword(const CrackInfo &crackInfo);

void writePrehashedPasswords(const CrackInfo &crackInfo);

std::string getCharSet();

void checkPrehashedPasswords(CrackInfo &crackInfo);

void bruteForce(CrackInfo &crackInfo);

bool tryPassword(CrackInfo &crackInfo, std::string password);

void bruteForceRecurse(std::string password, int index,
                       int maxDepth, CrackInfo &crackInfo);

std::string getExistingWalletFileName();

template <typename Iterator>
inline bool next_combination(const Iterator first, Iterator k,
                             const Iterator last)
{
   /* Credits: Thomas Draper */
   if ((first == last) || (first == k) || (last == k))
      return false;
   Iterator itr1 = first;
   Iterator itr2 = last;
   ++itr1;
   if (last == itr1)
      return false;
   itr1 = last;
   --itr1;
   itr1 = k;
   --itr2;
   while (first != itr1)
   {
      if (*--itr1 < *itr2)
      {
         Iterator j = k;
         while (!(*itr1 < *j)) ++j;
         std::iter_swap(itr1,j);
         ++itr1;
         ++j;
         itr2 = k;
         std::rotate(itr1,j,last);
         while (last != j)
         {
            ++j;
            ++itr2;
         }
         std::rotate(k,itr2,last);
         return true;
      }
   }
   std::rotate(first,k,last);
   return false;
}
