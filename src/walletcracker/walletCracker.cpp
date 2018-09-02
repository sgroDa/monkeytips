// Copyright (c) 2018, Zpalm
// GNU GPL V3

//////////////////////////////////////
#include <walletcracker/walletCracker.h>
//////////////////////////////////////

#include <boost/filesystem.hpp>

#include <CryptoNoteCore/Currency.h>

#include <Common/Util.h>
#include <Common/SignalHandler.h>
#include <Common/StringTools.h>

#include <fstream>

#include <Logging/FileLogger.h>
#include <Logging/LoggerManager.h>

#include <memory>

#include <NodeRpcProxy/NodeRpcProxy.h>

int main()
{
    /* Logging to a black hole... */
    Logging::LoggerManager logManager;
    Logging::LoggerRef logger(logManager, "zedwallet");

    /* Currency contains our coin parameters, such as decimal places, supply */
    CryptoNote::Currency currency
        = CryptoNote::CurrencyBuilder(logManager).currency();

    System::Dispatcher localDispatcher;
    System::Dispatcher *dispatcher = &localDispatcher;

    /* Our connection to monkeytipsd */
    std::unique_ptr<CryptoNote::INode> node(
        new CryptoNote::NodeRpcProxy("getbent", 666,
                                     logger.getLogger()));

    /* Create the wallet instance */
    CryptoNote::WalletGreen wallet(*dispatcher, currency, *node,
                                   logger.getLogger());

    /* Crack the wallet */
    crack(wallet);
}

void outputPassword(const CrackInfo &crackInfo)
{
    if (crackInfo.correctPassword == "")
    {
        std::cout << "You have no password, i.e. your password is the empty "
                  << "string: \"\"" << std::endl;
    }
    else
    {
        std::cout << "Your password is: " << crackInfo.correctPassword
                  << std::endl;
    }
}

void crack(CryptoNote::WalletGreen &wallet)
{
    CrackInfo crackInfo(wallet, getExistingWalletFileName());

    /* Try the prehashed passwords from the file */
    checkPrehashedPasswords(crackInfo);

    if (crackInfo.found)
    {
        outputPassword(crackInfo);
        return;
    }

    /* Didn't find it, lets get the char set and try and brute force */
    crackInfo.alphabet = getCharSet();

    bruteForce(crackInfo);

    if (crackInfo.found)
    {
        /* Write the brute forced passwords hashes to the file */
        writePrehashedPasswords(crackInfo);
        outputPassword(crackInfo);
        return;
    }
    else
    {
        std::cout << "Couldn't crack password, get fucked" << std::endl;
    }
}

std::string getPrehashedPath()
{
    return Tools::getDefaultDataDirectory() + "/prehashed-passwords.txt";
}

void writePrehashedPasswords(const CrackInfo &crackInfo)
{
    if (crackInfo.prehashed.empty())
    {
        return;
    }

    /* Create the directory(s) if they don't already exist */
    boost::filesystem::create_directories(Tools::getDefaultDataDirectory());

    std::ofstream file(getPrehashedPath());

    for (auto const& x : crackInfo.prehashed)
    {
        /* Write the password */
        file << x.first << std::endl
        /* Write the hex encoded key */
             << Common::podToHex(x.second.data) << std::endl;
    }
}

std::string getCharSet()
{
    /* lowercase alpha */
    std::string simpleCharSet = "abcdefghijklmnopqrstuvwxyz";

    /* alphanumeric, uppercase, space */
    std::string mediumCharSet = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ ";

    /* All ascii printable chars */
    std::string fullCharSet = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

    while (true)
    {
        std::string charSet;

        std::cout << "What character set do you want to use?"
                  << std::endl
                  << "A smaller char set will make cracking faster."
                  << std::endl
                  << std::endl
                  << "1 - Basic: a-z"
                  << std::endl
                  << "2 - Medium: a-z, A-Z, 0-9"
                  << std::endl
                  << "3 - Full: a-z, A-Z, 0-9, !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
                  << std::endl
                  << "Enter selection (1 - 3): ";

        std::getline(std::cin, charSet);

        if (charSet == "1")
        {
            return simpleCharSet;
        }
        else if (charSet == "2")
        {
            return mediumCharSet;
        }
        else if (charSet == "3")
        {
            return fullCharSet;
        }
        else
        {
            std::cout << "Bad input, expected a number from 1 to 3" << std::endl;
        }
    }
}

void checkPrehashedPasswords(CrackInfo &crackInfo)
{
    if (!boost::filesystem::exists(getPrehashedPath()))
    {
        std::cout << "No prehashed passwords found, brute forcing." 
                  << std::endl << std::endl;

        return;
    }
    else
    {
        std::cout << "Trying prehashed passwords..." << std::endl
                  << std::endl;
    }

    std::ifstream file(getPrehashedPath());

    /* The password we are currently testing */
    std::string password;

    std::string keyString;

    Crypto::chacha8_key key;

    /* First line is the password plaintext, second line is the chacha8_key
       as a string */
    while (std::getline(file, password), std::getline(file, keyString))
    {
        /* Convert from hex string to uint8_t array and assign */
        Common::podFromHex(keyString, key.data);

        /* Insert the prehashed password and key into the map for later
           writing */
        crackInfo.prehashed.insert({password, key});

        /* Yay, we found it! */
        if (crackInfo.wallet.isValidPassword(crackInfo.filename, key))
        {
            crackInfo.found = true;
            crackInfo.correctPassword = password;

            return;
        }
    }

    std::cout << "Failed to find password in prehashed passwords list..."
              << std::endl << std::endl;

    return;
}

void bruteForce(CrackInfo &crackInfo)
{
    std::cout << std::endl
              << "If your password is anything more than 3 characters, this "
              << "will take a long fucking time" << std::endl
              << "Hit Ctrl+C to exit early."
              << std::endl << std::endl;

    Crypto::chacha8_key key;
    Crypto::cn_context cnContext;

    if (!crackInfo.prehashed.empty())
    {
        /* Get the final item in the map (which is the last password we've
           tested, which should increase in length as we go, and set begin to
           the size of it. So, we only test passwords of lengths of a minimum
           that we've already tested */
        crackInfo.passwordResumeLength = crackInfo.prehashed.rbegin()->first.size();
    }

    /* If they ctrl+c, save the work we've done so far */
    Tools::SignalHandler::install([&crackInfo]
    {
        writePrehashedPasswords(crackInfo);
        exit(0);
    });

    /* Edge case of zero length password causes infinite recursion - don't
       try if we've already tried some passwords */
    if (crackInfo.passwordResumeLength == 1 && crackInfo.prehashed.empty())
    {
        std::cout << "Trying passwords of length 0" << std::endl;

        if (tryPassword(crackInfo, ""))
        {
            return;
        }
    }

    /* Start at the length of the passwords we ended on in the prehashed
       passwords */
    for (int i = crackInfo.passwordResumeLength; i < MAX_PASSWORD_LEN; i++)
    {
        std::cout << "Trying passwords of length " << i << std::endl;

        bruteForceRecurse(std::string(), 0, i, crackInfo);

        if (crackInfo.found)
        {
            return;
        }
    }
}

bool tryPassword(CrackInfo &crackInfo, std::string password)
{
    Crypto::chacha8_key key;
    Crypto::cn_context cnContext;

    /* Get our chacha8 key for this password */
    generate_chacha8_key(cnContext, password, key);

    crackInfo.prehashed.insert({password, key});

    if (crackInfo.wallet.isValidPassword(crackInfo.filename, key))
    {
        crackInfo.found = true;
        crackInfo.correctPassword = password;

        return true;
    }

    return false;
}

void bruteForceRecurse(std::string password, int index,
                       int maxDepth, CrackInfo &crackInfo)
{
    /* Make space for the new character */
    password.resize(password.size() + 1);

    for (size_t i = 0; i < crackInfo.alphabet.size(); i++)
    {
        /* Fill in the new character */
        password[index] = crackInfo.alphabet[i];

        if (index == maxDepth - 1)
        {
            /* We're on the first length iteration after trying the prehashed
               passwords, so we could have some duplicates. Check for this,
               and ignore them if they already exist. */
            if (index == crackInfo.passwordResumeLength
                      && crackInfo.prehashed.count(password) != 0)
            {
                continue;
            }

            /* Test the password */
            if (tryPassword(crackInfo, password))
            {
                return;
            }
        }
        else
        {
            /* Recurse */
            bruteForceRecurse(password, index + 1, maxDepth, crackInfo);

            if (crackInfo.found)
            {
                return;
            }
        }
    }
}

std::string getExistingWalletFileName()
{
    bool initial = true;

    std::string walletName;

    while (true)
    {
        std::cout << "What is the name of the wallet file you want to crack?: ";
        std::getline(std::cin, walletName);

        std::string walletFileName = walletName + ".wallet";

        if (walletName == "")
        {
            std::cout << "Wallet name can't be blank! Try again."
                      << std::endl;
        }
        /* Allow people to enter wallet name with or without file extension */
        else if (boost::filesystem::exists(walletName))
        {
            return walletName;
        }
        else if (boost::filesystem::exists(walletFileName))
        {
            return walletFileName;
        }
        else
        {
            std::cout << "File doesn't exist, try again." << std::endl;
        }
    }
}
