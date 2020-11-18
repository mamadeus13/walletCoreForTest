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

/*
    auto hash0 = parse_hex("388b2d6d838db6e495a1eb1e31c95be09c7eb6dfc84ab3a43571ac7a230e2cb7");

    int64_t utxo0Amount = 274221 ; 


    Proto::SigningInput input;
    input.set_hash_type(hashTypeForCoin(TWCoinTypeBitcoin));
    input.set_amount(200'000'000);
    input.set_byte_fee(1);
    input.set_to_address("bc1qphxqjzcq58eepq0s4w80ucxwg3n7d4hqxty5wn");
    
    auto utxoKey0 = PrivateKey(parse_hex("f92378e54fc4e42091e3e508e604dc9a259ff4abe441c3d04b8f8ee97dc4540b"));
    auto pubKey0 = utxoKey0.getPublicKey(TWPublicKeyTypeSECP256k1);
    auto utxoPubkeyHash0 = Hash::ripemd(Hash::sha256(pubKey0.bytes));

    input.add_private_key(utxoKey0.bytes.data(), utxoKey0.bytes.size());
    std::string scrPubStr = "0014" + hex(utxoPubkeyHash0);  

    auto scriptPub1 = Script(parse_hex(scrPubStr));

    Data scriptHash;
    scriptPub1.matchPayToWitnessPublicKeyHash(scriptHash);
    auto scriptHashHex = hex(scriptHash);
    

    auto redeemScript = Script::buildPayToPublicKeyHash(parse_hex(hex(utxoPubkeyHash0)));
    auto scriptString = std::string(redeemScript.bytes.begin(), redeemScript.bytes.end());
    (*input.mutable_scripts())[scriptHashHex] = scriptString;


    auto utxo0 = input.add_utxo();
    auto utxo0Script = parse_hex("0014f1000f7cbe080a3ea92a45925852a4a9479d508d");
    utxo0->set_script(utxo0Script.data(), utxo0Script.size());
    utxo0->set_amount(utxo0Amount);
    utxo0->mutable_out_point()->set_hash(hash0.data(), hash0.size());
    utxo0->mutable_out_point()->set_index(0);
    utxo0->mutable_out_point()->set_sequence(UINT32_MAX);
*/
    // input.release_plan
////input completed

    // TWAnySignerSign(input.to, TW::Bitcoin);

    // auto unsigned Tx = Transaction(1, 0x492);
    // unsignedTx.inputs = input ; 


    // auto outpoint0 = TW::Bitcoin::OutPoint(hash0, 44);







 /*   
    auto unsignedTx = Transaction(1, 0x11);

    auto outpoint0 = TW::Bitcoin::OutPoint(hash0, 44);
    unsignedTx.inputs.emplace_back(outpoint0, Script(), 0xffffffee);

    // auto hash1 = parse_hex("ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a");
    // auto outpoint1 = TW::Bitcoin::OutPoint(hash1, 1);
    // unsignedTx.inputs.emplace_back(outpoint1, Script(), UINT32_MAX);

    auto outScript0 = Script(parse_hex("76a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac"));
    unsignedTx.outputs.emplace_back(112340000, outScript0);

    auto outScript1 = Script(parse_hex("76a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac"));
    unsignedTx.outputs.emplace_back(223450000, outScript1);

    Data unsignedData;
    unsignedTx.encode(unsignedData, Transaction::SegwitFormatMode::Segwit);
    std::cout<<"the Data is : \n" << hex(unsignedData) <<std::endl;


//     auto data = hex(unsignedData);

    
//    // char command[200];  
//     auto commandStr =  "../libnspv/bitcoin-send-tx " + data;
//     //sprintf(command , "../libnspv/bitcoin-send-tx %s" , data.c_str());

//     std::cout << "out command : \n"  << commandStr <<std::endl ;
//     auto i = std::system( commandStr.c_str());
//     printf("out value is %d \n" , i );

*/




    auto coin = TWCoinTypeBitcoin;
    auto ownAddress = "bc1q0d43anc6lkd52yjrw2f3qfl27tan29k8ukryd2";
    auto ownPrivateKey = "a182e53e814f87e376ced3f3bd845f2e50758e55558b3bf49fc6d5e2fe9ef095";
    auto toAddress0 = "bc1qphxqjzcq58eepq0s4w80ucxwg3n7d4hqxty5wn";
    auto toAddress1 = "bc1q0d43anc6lkd52yjrw2f3qfl27tan29k8ukryd2";
    auto utxo0Amount = 257171;
    auto toAmount0 = 227171;
    auto toAmount1 = 99'328;

    auto unsignedTx = Transaction(1, 0);

    auto hash0 = parse_hex("6a1a9ea47c62ee2a14205850018936c53a6b08a290b8af6d83224975a1f859e8");
    std::reverse(hash0.begin(), hash0.end());
    auto outpoint0 = TW::Bitcoin::OutPoint(hash0, 0);//44 or zero for fucking crash 
    auto mmdScript =  Script(parse_hex("00147b6b1ecf1afd9b45124372931027eaf2fb3516c7"));
    std::cout << "is P2WPKH : "  << mmdScript.isPayToWitnessPublicKeyHash() << std::endl ;
    unsignedTx.inputs.emplace_back(outpoint0,mmdScript, UINT32_MAX); //zero to UNINT32_MAX 

    auto lockingScript0 = Script::lockScriptForAddress(toAddress0, coin);
    unsignedTx.outputs.push_back(TransactionOutput(toAmount0, lockingScript0));
    // auto lockingScript1 = Script::lockScriptForAddress(toAddress1, coin);
    // unsignedTx.outputs.push_back(TransactionOutput(toAmount1, lockingScript1));
    // change
    // auto lockingScript2 = Script::lockScriptForAddress(ownAddress, coin);
    // unsignedTx.outputs.push_back(TransactionOutput(utxo0Amount - toAmount0 - 172, lockingScript2));

    Data unsignedData;
    unsignedTx.encode(unsignedData, Transaction::SegwitFormatMode::Segwit);
         std::cout<<"the Data is : \n" << hex(unsignedData) <<std::endl;


    
 
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

    auto redeemScript0 = Script::buildPayToWitnessPublicKeyHash(keyHashIn0);
    // EXPECT_EQ(hex(redeemScript0.bytes), "76a9145c74be45eb45a3459050667529022d9df8a1ecff88ac");
    std::cout << "redeemScript0 :  \n" <<  hex(redeemScript0.bytes) <<std::endl ; 
    auto hashType = TWBitcoinSigHashType::TWBitcoinSigHashTypeAll;
    std::cout << "priviousoutputIndx  : " << unsignedTx.inputs[0].previousOutput.index << std::endl; 
    Data sighash = unsignedTx.getSignatureHash(redeemScript0, unsignedTx.inputs[0].previousOutput.index,
        hashType, utxo0Amount, static_cast<SignatureVersion>(unsignedTx.version));
    auto sig = privkey.signAsDER(sighash, TWCurveSECP256k1);
    // ASSERT_FALSE(sig.empty());
    sig.push_back(hashType);
    // EXPECT_EQ(hex(sig), "30450221008d88197a37ffcb51ecacc7e826aa588cb1068a107a82373c4b54ec42318a395c02204abbf5408504614d8f943d67e7873506c575e85a5e1bd92a02cd345e5192a82701");
    
    // add witness stack
    unsignedTx.inputs[0].scriptWitness.push_back(sig);
    // unsignedTx.inputs[0].scriptWitness.push_back(pubkey.bytes);
    unsignedTx.inputs[0].encodeWitness(sig);

    unsignedData.clear();
    unsignedTx.encode(unsignedData, Transaction::SegwitFormatMode::IfHasWitness);
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


    // unsignedTx.sign


    auto data = hex(unsignedData);

    std::cout << data << std::endl ; 
    
   // char command[200];  
    auto commandStr =  "../libnspv/bitcoin-send-tx " + data;
    // sprintf(command , "../libnspv/bitcoin-send-tx %s" , data.c_str());

    std::cout << "out command : \n"  << commandStr <<std::endl ;
    auto i = std::system( commandStr.c_str());
    printf("out value is %d \n" , i );


}
