#include "Bitcoin/OutPoint.h"
#include "Bitcoin/Script.h"
#include "Bitcoin/Transaction.h"
#include "Bitcoin/TransactionBuilder.h"
#include "Bitcoin/TransactionSigner.h"
#include "Bitcoin/SigHashType.h"
#include "Hash.h"
#include "HexCoding.h"
#include "PrivateKey.h"
#include "proto/Bitcoin.pb.h"
#include "../tests/Bitcoin/TxComparisonHelper.h"
#include "../tests/interface/TWTestUtilities.h"

#include <TrustWalletCore/TWBitcoinScript.h>
#include <TrustWalletCore/TWAnySigner.h>
#include <TrustWalletCore/TWHash.h>
#include <TrustWalletCore/TWPrivateKey.h>

#include <gtest/gtest.h>
#include <cassert>




using namespace TW;
using namespace TW::Bitcoin;

int main () 
{
    auto coin = TWCoinTypeBitcoin;
    auto ownAddress = "bc1q7yqq7l97pq9ra2f2gkf9s54y49re65ydgydy35";
    auto ownPrivateKey = "f92378e54fc4e42091e3e508e604dc9a259ff4abe441c3d04b8f8ee97dc4540b";
    auto toAddress0 = "bc1qphxqjzcq58eepq0s4w80ucxwg3n7d4hqxty5wn";
    auto toAddress1 = "bc1q0d43anc6lkd52yjrw2f3qfl27tan29k8ukryd2";
    auto utxo0Amount = 274'221;
    auto toAmount0 = 174'221;
    auto toAmount1 = 99'328;

    auto unsignedTx = Transaction(1, 0);

    auto hash0 = parse_hex("388b2d6d838db6e495a1eb1e31c95be09c7eb6dfc84ab3a43571ac7a230e2cb7");
    std::reverse(hash0.begin(), hash0.end());
    auto outpoint0 = TW::Bitcoin::OutPoint(hash0, 0);
    unsignedTx.inputs.emplace_back(outpoint0, Script(), UINT32_MAX);

    auto lockingScript0 = Script::lockScriptForAddress(toAddress0, coin);
    unsignedTx.outputs.push_back(TransactionOutput(toAmount0, lockingScript0));
    auto lockingScript1 = Script::lockScriptForAddress(toAddress1, coin);
    unsignedTx.outputs.push_back(TransactionOutput(toAmount1, lockingScript1));
    // change
    auto lockingScript2 = Script::lockScriptForAddress(ownAddress, coin);
    unsignedTx.outputs.push_back(TransactionOutput(utxo0Amount - toAmount0 - toAmount1 - 172, lockingScript2));

    Data unsignedData;
    unsignedTx.encode(unsignedData, Transaction::SegwitFormatMode::Segwit);
        // std::cout<<"the Data is : \n" << hex(unsignedData) <<std::endl;


    
 
    // EXPECT_EQ(unsignedData.size(), 147);
    // EXPECT_EQ(hex(unsignedData), // printed using prettyPrintTransaction
    //     "01000000" // version
    //     "0001" // marker & flag
    //     "01" // inputs
    //         "fe554f0068ed898680772f7a4d3e0a97385f4df20fff5d0278463ca6ad36e7bb"  "00000000"  "00"  ""  "ffffffff"
    //     "03" // outputs
    //         "40420f0000000000"  "16"  "001445a70b76fbdea0c9d5598c51cdd1d8ab455ab965"
    //         "80841e0000000000"  "16"  "0014e7d0b03506234b334e742192bd48968584f4a7f1"
    //         "c9fe0c0000000000"  "16"  "00145c74be45eb45a3459050667529022d9df8a1ecff"
    //     // witness
    //         "00"
    //     "00000000" // nLockTime
    // );

    // add signature

    auto privkey = PrivateKey(parse_hex(ownPrivateKey));
    auto pubkey = PrivateKey(privkey).getPublicKey(TWPublicKeyTypeSECP256k1);
    // EXPECT_EQ(hex(pubkey.bytes), "036739829f2cfec79cfe6aaf1c22ecb7d4867dfd8ab4deb7121b36a00ab646caed");

    auto utxo0Script = Script::lockScriptForAddress(ownAddress, coin); // buildPayToWitnessProgram()
    Data keyHashIn0;
    // EXPECT_TRUE(utxo0Script.matchPayToWitnessPublicKeyHash(keyHashIn0));
    utxo0Script.matchPayToWitnessPublicKeyHash(keyHashIn0);

    // EXPECT_EQ(hex(keyHashIn0), "5c74be45eb45a3459050667529022d9df8a1ecff");

    auto redeemScript0 = Script::buildPayToPublicKeyHash(keyHashIn0);
    // EXPECT_EQ(hex(redeemScript0.bytes), "76a9145c74be45eb45a3459050667529022d9df8a1ecff88ac");

    auto hashType = TWBitcoinSigHashType::TWBitcoinSigHashTypeAll;
    Data sighash = unsignedTx.getSignatureHash(redeemScript0, unsignedTx.inputs[0].previousOutput.index,
        hashType, utxo0Amount, static_cast<SignatureVersion>(unsignedTx.version));
    auto sig = privkey.signAsDER(sighash, TWCurveSECP256k1);
    // ASSERT_FALSE(sig.empty());
    sig.push_back(hashType);
    // EXPECT_EQ(hex(sig), "30450221008d88197a37ffcb51ecacc7e826aa588cb1068a107a82373c4b54ec42318a395c02204abbf5408504614d8f943d67e7873506c575e85a5e1bd92a02cd345e5192a82701");
    
    // add witness stack
    unsignedTx.inputs[0].scriptWitness.push_back(sig);
    unsignedTx.inputs[0].scriptWitness.push_back(pubkey.bytes);

    unsignedData.clear();
    unsignedTx.encode(unsignedData, Transaction::SegwitFormatMode::Segwit);
    // EXPECT_EQ(unsignedData.size(), 254);
    // // https://blockchair.com/litecoin/transaction/9e3fe98565a904d2da5ec1b3ba9d2b3376dfc074f43d113ce1caac01bf51b34c
    // EXPECT_EQ(hex(unsignedData), // printed using prettyPrintTransaction
    //     "01000000" // version
    //     "0001" // marker & flag
    //     "01" // inputs
    //         "fe554f0068ed898680772f7a4d3e0a97385f4df20fff5d0278463ca6ad36e7bb"  "00000000"  "00"  ""  "ffffffff"
    //     "03" // outputs
    //         "40420f0000000000"  "16"  "001445a70b76fbdea0c9d5598c51cdd1d8ab455ab965"
    //         "80841e0000000000"  "16"  "0014e7d0b03506234b334e742192bd48968584f4a7f1"
    //         "c9fe0c0000000000"  "16"  "00145c74be45eb45a3459050667529022d9df8a1ecff"
    //     // witness
    //         "02"
    //             "48"  "30450221008d88197a37ffcb51ecacc7e826aa588cb1068a107a82373c4b54ec42318a395c02204abbf5408504614d8f943d67e7873506c575e85a5e1bd92a02cd345e5192a82701"
    //             "21"  "036739829f2cfec79cfe6aaf1c22ecb7d4867dfd8ab4deb7121b36a00ab646caed"
    //     "00000000" // nLockTime
    // );
    std::cout<<"the Data is : \n" << hex(unsignedData) <<std::endl;


    auto data = hex(unsignedData);

    
   // char command[200];  
    auto commandStr =  "../libnspv/bitcoin-send-tx " + data;
    //sprintf(command , "../libnspv/bitcoin-send-tx %s" , data.c_str());

    std::cout << "out command : \n"  << commandStr <<std::endl ;
    auto i = std::system( commandStr.c_str());
    printf("out value is %d \n" , i );


}