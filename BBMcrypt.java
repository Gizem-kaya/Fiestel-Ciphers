
/**
 * 
 * BBMcrpyt.java
 * 
 *  
 */

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Base64;
import java.util.BitSet;
import java.math.BigInteger;
import java.util.Base64.Decoder;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

class BBMcrypt {
    private static boolean ENC;
    private static String MODE; // enc/dec mode (ECB, CBC, OFB)
    private static BitSet key;
    private static BitSet plainT; // plaintext
    private static BitSet cipherT; // ciphertext
    private static String inFile; // name of the input file
    private static String outFile; // name of the output file
    private static BitSet iv; // initialization vector
    private static int textLen;
    

    public static void main(String[] args) throws IOException {
        // checks argument length
        int argLen = args.length;
        if (argLen != 9)
            throw new IllegalArgumentException();

        BBMcrypt bc = new BBMcrypt();
        key = new BitSet();
        plainT = new BitSet();
        cipherT = new BitSet();
        // initialize vector
        iv = initializeVector();
        textLen = 0;

        if (args[0].equals("enc"))
            ENC = true;
        else
            ENC = false;

        // reads arguments
        for (int i = 1; i < argLen; i++) {
            if (args[i].equals("-K"))
                bc.readKey(args[i+1]);
            else if (args[i].equals("-I")) 
            {
                inFile = args[i+1];
                if (ENC)
                    bc.readText(inFile, true);
                else
                    bc.readText(inFile, false);
            } else if (args[i].equals("-O"))
                outFile = args[i + 1];
            else if (args[i].equals("-M"))
                MODE = args[i + 1];
        }

        // initialize the enc/dec with the specified mode
        if (MODE.equals("ECB"))
            ECB();
        if (MODE.equals("CBC"))
            CBC(iv);
        if (MODE.equals("OFB"))
            OFB(iv);
    }

    private static BitSet initializeVector()
    {
        BitSet iv = new BitSet();
        for (int i = 0; i < 96; i++)
            iv.set(i);
        return iv;
    }

    private static BitSet[] BitSetArrayInit(int size)
    {
        BitSet[] arr = new BitSet[size];
        for (int j = 0; j < size; j++)
        {
            arr[j] = new BitSet();
        }
        return arr;
    }

    private static void ECB() {
        if (ENC) // encryption mode
        {
            BitSet midText = new BitSet();
            // number of blocks
            int block = textLen/96;
            BitSet[] cipherArr = BitSetArrayInit(block);
            // create a copy of key
            BitSet blockKey = (BitSet) key.clone();
            // starting index of the first block
            int start = 0;
            // repetition for each block of data/text
            for (int i = 0; i < block; i++)
            {
                // divide the block into half
                BitSet left = plainT.get(start, start+48); // current left side of the block
                BitSet right = plainT.get(start+48, start+96); // current right side of the block
                BitSet nextLeft;
                BitSet nextRight;

                // 10 round encryption
                for (int round = 0; round < 10; round++)
                {	
                    // gets the shifted key for this block
                    blockKey = updateKey(blockKey);
                    
                    BitSet permutedKey = new BitSet(48);
                    if (round%2 == 0)
                        permutedKey = permutedKey(blockKey, true);
                    else if (round%2 == 1)
                        permutedKey = permutedKey(blockKey, false);

                    nextLeft = (BitSet) right.clone();
                    left.xor(scramble(right, permutedKey));
                    nextRight = (BitSet) left.clone();
                    // updates ciphertext as the plaintext encrypted
                    midText = updateText(nextLeft, nextRight);
                    // assigns next values to go next round of encryption
                    left = (BitSet) nextLeft.clone();
                    right = (BitSet) nextRight.clone();
                }
                // shifts by 96 to reach the next block of plaintext
                start += 96;
                blockKey = (BitSet) key.clone();
                cipherArr[i] = (BitSet) midText.clone();
            }
            cipherT = connectTexts(cipherArr, block);
            writeOutFile(cipherT);
        } 
        else // decryption mode
        {
            // midText stands for the temporary text that is being decrypted throughout the process
            BitSet midText = new BitSet(96);
            int block = textLen/96;
            BitSet[] midTexts = BitSetArrayInit(block);
            BitSet blockKey = (BitSet) key.clone();
            int start = 0;
            BitSet[] keyArr = new BitSet[10];
            
            for (int i = 0; i < block; i++)
	        {	           
            	for (int k = 9; k > -1; k--)
	            {	
            		
            		keyArr[k] = updateKey(blockKey);		           
		            blockKey = (BitSet) (keyArr[k]).clone();
	            }
                BitSet left = cipherT.get(start, start+48); // current left side of the block
                BitSet right = cipherT.get(start+48, start+96); // current right side of the block
                BitSet prevLeft;
                BitSet prevRight;

                // 10 rounds of decryption
                for (int round = 0; round < 10; round++)
                {
                    blockKey = (BitSet) keyArr[round].clone();
                    BitSet permutedKey;
                    if (round%2 == 0)
                        permutedKey = permutedKey(blockKey, false);
                    else
                        permutedKey = permutedKey(blockKey, true);
                                    
                    prevRight = (BitSet) left.clone();
                    right.xor(scramble(left, permutedKey));
                    prevLeft = (BitSet) right.clone();
                    midText = updateText(prevLeft, prevRight);
                    left = (BitSet) prevLeft.clone();
                    right = (BitSet) prevRight.clone();
                }
                start += 96;
                midTexts[i] = (BitSet) midText.clone();
                blockKey = (BitSet) key.clone();
            }
            plainT = connectTexts(midTexts, block);
            writeOutFile(plainT);
        }
    }

    private static BitSet connectTexts(BitSet[] texts, int block)
    {
        BitSet mainText = new BitSet();
        int start = 0;
        for (int i = 0; i < block; i++)
        {
            BitSet text = texts[i];
            for (int j = 0; j < 96; j++)
            {
                if (text.get(j))
                    mainText.set(j+start);
            }
            start+=96;
        }
        return mainText;
    }

    /**
     * applies left circular shift to obtain updated key.
     */
    private static BitSet updateKey(BitSet key)
    {
        BitSet updatedKey = new BitSet();

        if(key.get(0)) updatedKey.set(95);
        for (int i=1; i<96; i++){
            if(key.get(i)) updatedKey.set(i-1);
        }
        
        //System.out.println(key);
        //System.out.println(updatedKey);
        return updatedKey;
    }

    private static BitSet permutedKey(BitSet key, boolean roundIsEven){
        
        BitSet permuted = new BitSet();
        if (roundIsEven){
            for (int i=0; i<48; i++){
                if(key.get(i*2)) permuted.set(i);
            }
        }
        else{
            for (int i=0; i<48; i++){
                if(key.get((i*2)+1)) permuted.set(i);
            }
        }

        //System.out.println(permuted);
        return permuted;
    }

    private static BitSet updateText(BitSet left, BitSet right) {
        BitSet text = new BitSet();
        for (int l = 0; l < 48; l++) {
            if (left.get(l)) // if the bit is 1; returns true
                text.set(l, true);
        }
        for (int r = 48; r < 96; r++) {
            if (right.get(r-48)) // if the bit is 1; returns true
                text.set(r, true);
        }
        return text;
    }

    
    private static void CBC(BitSet iv) {
        if (ENC) 
        {
            // make a copy of plaintext to obtain ciphertext by modifying it at each round
            BitSet plainCopy = (BitSet) plainT.clone();
            // number of blocks
            int block = textLen/96;
            BitSet[] cipherArr = BitSetArrayInit(block);
            BitSet blockKey = (BitSet) key.clone();
            int start = 0;
            for (int i = 0; i < block; i++)
            {
                // gets the block to be modified
                BitSet midCipher = plainCopy.get(start, start+96);         
                BitSet nextLeft;
                BitSet nextRight;
                midCipher.xor(iv);
                BitSet left = midCipher.get(0, 48);
                BitSet right = midCipher.get(48, 96);
                
                // 10 rounds of encryption
                for (int round = 0; round < 10; round++) {
                    // the key of the block updates for the next round
                    blockKey = updateKey(blockKey);
                    BitSet permutedKey = new BitSet();
                    if (round%2 == 0)
                        permutedKey = permutedKey(blockKey, true);
                    else
                        permutedKey = permutedKey(blockKey, false);

                    nextLeft = (BitSet) right.clone();
                    left.xor(scramble(right, permutedKey));
                    nextRight = (BitSet) left.clone();
                    // updates ciphertext as the plaintext encrypted
                    midCipher = updateText(nextLeft, nextRight);
                    
                    // assigns next values to go next round of encryption
                    left = (BitSet) nextLeft.clone();
                    right = (BitSet) nextRight.clone();
                    
                }
                // add mid cipher to the cipher array
                cipherArr[i] = (BitSet) midCipher.clone();
                // shifts by 96 to reach the next block of plaintext
                start += 96;
                iv = (BitSet) midCipher.clone();
                blockKey = (BitSet) key.clone();
            }
            cipherT = connectTexts(cipherArr, block);
            writeOutFile(cipherT);
        }
        else
        {
            // clone the cipher text to modify
            BitSet text = (BitSet) cipherT.clone();
            int block = textLen/96;
            BitSet[] midTexts = BitSetArrayInit(block);
            BitSet blockKey = (BitSet) key.clone();
            int start = 0;
            BitSet[] keyArr = new BitSet[10];
            
            for (int i = 0; i < block; i++)
	        {	           
            	for (int k = 9; k > -1; k--)
	            {	          		
            		keyArr[k] = updateKey(blockKey);		           
		            blockKey = (BitSet) (keyArr[k]).clone();
	            }	           
            	
                // gets the block to be modified
                BitSet midText = text.get(start, start+96);
                BitSet nextIV = (BitSet) midText.clone();
                BitSet left = midText.get(0, 48);
                BitSet right = midText.get(48, 96);
                BitSet prevLeft;
                BitSet prevRight;

                for (int round = 0; round < 10; round++)
                {
                	blockKey = (BitSet) keyArr[round].clone();
                    BitSet permutedKey;
                    if (round%2 == 0)
                        permutedKey = permutedKey(blockKey, false);
                    else
                        permutedKey = permutedKey(blockKey, true);
                                    
                    prevRight = (BitSet) left.clone();
                    right.xor(scramble(left, permutedKey));
                    prevLeft = (BitSet) right.clone();
                    midText = updateText(prevLeft, prevRight);
                    left = (BitSet) prevLeft.clone();
                    right = (BitSet) prevRight.clone();
                    
                }
                start += 96;
                midText.xor(iv);
                midTexts[i] = (BitSet) midText.clone();
                iv = (BitSet) nextIV.clone();
                blockKey = (BitSet) key.clone();
            }
            plainT = connectTexts(midTexts, block);
            writeOutFile(plainT);
        }
    }

    private static void OFB(BitSet iv) {
        if (ENC)
        {
            // make a copy of plaintext to obtain ciphertext by modifying it at each round
            BitSet plainCopy = (BitSet) plainT.clone();
            // number of blocks
            int block = textLen/96;
            BitSet[] cipherArr = BitSetArrayInit(block);
            BitSet blockKey = (BitSet) key.clone();
            BitSet nextVector = (BitSet) iv.clone();
            int start = 0;
            for (int i = 0; i < block; i++)
            {
                BitSet plaintext = plainCopy.get(start, start+96);
                BitSet left = iv.get(0, 48);
                BitSet right = iv.get(48, 96);
                BitSet nextLeft;
                BitSet nextRight;

                // 10 rounds of encryption
                for (int round = 0; round < 10; round++)
                {
                    // the key of the block updates for the next round
                    blockKey = updateKey(blockKey);
                   
                    BitSet permutedKey = new BitSet();

                    if (round%2 == 0)
                        permutedKey = permutedKey(blockKey, true);
                    else
                        permutedKey = permutedKey(blockKey, false);
                    
                    nextLeft = (BitSet) right.clone();
                    left.xor(scramble(right, permutedKey));
                    nextRight = (BitSet) left.clone();
                    // updates ciphertext as the plaintext encrypted
                    iv = updateText(nextLeft, nextRight);
                    // assigns next values to go next round of encryption
                    left = (BitSet) nextLeft.clone();
                    right = (BitSet) nextRight.clone();
                }
                // store iv for the next round
                nextVector= (BitSet) iv.clone();
                // xor the result of encryption with plaintext
                iv.xor(plaintext);
                cipherArr[i] = (BitSet) iv.clone();
                start+= 96;
                blockKey = (BitSet) key.clone();
                iv = (BitSet) nextVector.clone();
            }  
            cipherT = connectTexts(cipherArr, block);
            writeOutFile(cipherT);
        } 
        else
        {
            // make a copy of plaintext to obtain ciphertext by modifying it at each round
            BitSet cipherCopy = (BitSet) cipherT.clone();
            // number of blocks
            int block = textLen/96;
            BitSet[] midTexts = BitSetArrayInit(block);
            BitSet blockKey = (BitSet) key.clone();
            BitSet nextVector = (BitSet) iv.clone();
            int start = 0;
            BitSet[] keyArr = new BitSet[10];
            
            for (int i = 0; i < block; i++)
	        {	           
            	for (int k = 9; k > -1; k--)
	            {	          		
            		keyArr[k] = updateKey(blockKey);           		
		            blockKey = (BitSet) (keyArr[k]).clone();
		            
	            }	           
            	
                // to use in xor operation
                BitSet ciphertext = cipherCopy.get(start, start+96);
                BitSet left = iv.get(0, 48);
                BitSet right = iv.get(48, 96);
                BitSet prevLeft;
                BitSet prevRight;
                BitSet midText = new BitSet();
                
                // 10 rounds of decryption
                for (int round = 0; round < 10; round++)
                {
                	blockKey = (BitSet) keyArr[round].clone();
                    BitSet permutedKey;
                    if (round%2 == 0)
                        permutedKey = permutedKey(blockKey, false);
                    else
                        permutedKey = permutedKey(blockKey, true);
                                     
                    prevRight = (BitSet) left.clone();
                    right.xor(scramble(left, permutedKey));
                    prevLeft = (BitSet) right.clone();
                    midText = updateText(prevLeft, prevRight);
                    left = (BitSet) prevLeft.clone();
                    right = (BitSet) prevRight.clone();
                    
                }
                
                
                nextVector= (BitSet) midText.clone();
                // xor the result of encryption with plaintext
                midText.xor(ciphertext);
                midTexts[i] = (BitSet) midText.clone();
                start+= 96;
                blockKey = (BitSet) key.clone();
                iv = (BitSet) nextVector.clone();
            }  
            plainT = connectTexts(midTexts, block);
            writeOutFile(plainT);
        }
    }

    private static BitSet scramble(BitSet bitset, BitSet key)
    {

        /** 
         * 
         *  Creation of the Substitution Box 
         * 
        */

        BitSet [][] substitutionBox = new BitSet[4][16];

        for (int i=0; i < 4; i++){
            for (int j=0; j < 16; j++)
                substitutionBox[i][j]  = new BitSet(); 
        }

        substitutionBox[0][0].set(2);
        substitutionBox[0][1].set(0); substitutionBox[0][1].set(1);
        substitutionBox[0][2].set(1);
        substitutionBox[0][3].set(3);
        substitutionBox[0][4].set(1);substitutionBox[0][4].set(2);substitutionBox[0][4].set(3);
        substitutionBox[0][5].set(0);substitutionBox[0][5].set(2);
        substitutionBox[0][6].set(0);substitutionBox[0][6].set(2);substitutionBox[0][6].set(3);
        substitutionBox[0][7].set(1);substitutionBox[0][7].set(2);
        substitutionBox[0][8].set(0);
        substitutionBox[0][9].set(1);substitutionBox[0][9].set(3);
        substitutionBox[0][10].set(2);substitutionBox[0][10].set(3);
        substitutionBox[0][11].set(0);substitutionBox[0][11].set(1);substitutionBox[0][11].set(2);substitutionBox[0][11].set(3);
        substitutionBox[0][12].set(0);substitutionBox[0][12].set(1);substitutionBox[0][12].set(3);
        substitutionBox[0][14].set(0);substitutionBox[0][14].set(1);substitutionBox[0][14].set(2);
        substitutionBox[0][15].set(0);substitutionBox[0][15].set(3);
        
        substitutionBox[1][0].set(0);substitutionBox[1][0].set(1);substitutionBox[1][0].set(2);
        substitutionBox[1][1].set(0); substitutionBox[1][1].set(2);substitutionBox[1][1].set(3);
        substitutionBox[1][2].set(2);
        substitutionBox[1][3].set(0);substitutionBox[1][3].set(1);
        substitutionBox[1][4].set(1);
        substitutionBox[1][5].set(1);substitutionBox[1][5].set(2);substitutionBox[1][5].set(3);
        substitutionBox[1][6].set(0);substitutionBox[1][6].set(1);substitutionBox[1][6].set(3);
        substitutionBox[1][7].set(3);
        substitutionBox[1][8].set(1);substitutionBox[1][8].set(3);
        substitutionBox[1][10].set(0);substitutionBox[1][10].set(1);substitutionBox[1][10].set(2);substitutionBox[1][10].set(3);
        substitutionBox[1][11].set(0);substitutionBox[1][11].set(2);
        substitutionBox[1][12].set(2);substitutionBox[1][12].set(3);
        substitutionBox[1][13].set(0);substitutionBox[1][13].set(3);
        substitutionBox[1][14].set(0);
        substitutionBox[1][15].set(1);substitutionBox[1][15].set(2);

        substitutionBox[2][0].set(1);
        substitutionBox[2][1].set(2);
        substitutionBox[2][2].set(3);
        substitutionBox[2][3].set(0);substitutionBox[2][3].set(2);substitutionBox[2][3].set(3);
        substitutionBox[2][4].set(0);substitutionBox[2][4].set(2);
        substitutionBox[2][5].set(0);substitutionBox[2][5].set(1);substitutionBox[2][5].set(3);
        substitutionBox[2][6].set(1);substitutionBox[2][6].set(2);substitutionBox[2][6].set(3);
        substitutionBox[2][7].set(0);
        substitutionBox[2][8].set(0);substitutionBox[2][8].set(1);substitutionBox[2][8].set(2);substitutionBox[2][8].set(3);
        substitutionBox[2][9].set(0);substitutionBox[2][9].set(3);
        substitutionBox[2][10].set(0);substitutionBox[2][10].set(1);
        substitutionBox[2][11].set(1);substitutionBox[2][11].set(3);
        substitutionBox[2][12].set(1);substitutionBox[2][12].set(2);
        substitutionBox[2][13].set(2);substitutionBox[2][13].set(3);
        substitutionBox[2][15].set(0);substitutionBox[2][15].set(1);substitutionBox[2][15].set(2);

        substitutionBox[3][0].set(0);substitutionBox[3][0].set(2);substitutionBox[3][0].set(3);
        substitutionBox[3][1].set(0);
        substitutionBox[3][2].set(0);substitutionBox[3][2].set(1);
        substitutionBox[3][3].set(1);substitutionBox[3][3].set(2);substitutionBox[3][3].set(3);
        substitutionBox[3][4].set(3);
        substitutionBox[3][5].set(0);substitutionBox[3][5].set(1);substitutionBox[3][5].set(2);
        substitutionBox[3][6].set(2);
        substitutionBox[3][7].set(0);substitutionBox[3][7].set(1);substitutionBox[3][7].set(3);
        substitutionBox[3][8].set(1);substitutionBox[3][8].set(2);
        substitutionBox[3][9].set(0); substitutionBox[3][9].set(1);substitutionBox[3][9].set(2); substitutionBox[3][9].set(3);
        substitutionBox[3][11].set(0);substitutionBox[3][11].set(3);
        substitutionBox[3][12].set(0);substitutionBox[3][12].set(2);
        substitutionBox[3][13].set(1);
        substitutionBox[3][14].set(1);substitutionBox[3][14].set(3);
        substitutionBox[3][15].set(2);substitutionBox[3][15].set(3);
        //System.out.println(substitutionBox[0][0]);


    /**
     * 
     *  Partitioning Operations
     * 
     */
        BitSet result = new BitSet();

        bitset.xor(key);
        //System.out.println(bitset);
        BitSet [] piecesBeforeSubs = new BitSet[12];
        BitSet [] piecesAfterSubs = new BitSet[12];
        int counter = 8;

        for (int k=0; k<12; k++){

            piecesBeforeSubs[k] = new BitSet();
            piecesAfterSubs[k] = new BitSet();

            if (k<8){
                piecesBeforeSubs[k] = bitset.get(6*k, 6*(k+1));
                
            }
            else{
                
                BitSet Px, Py;
                Px = (BitSet) piecesBeforeSubs[k-counter].clone(); 
                Py = (BitSet) piecesBeforeSubs[k-counter+1].clone();
                Px.xor(Py);
                piecesBeforeSubs[k] = Px;
                counter--;    
                
            }

            //System.out.println(piecesBeforeSubs[k]);
            int outerBits;
            if (piecesBeforeSubs[k].get(0) && piecesBeforeSubs[k].get(5)) outerBits = 3;
            else if(piecesBeforeSubs[k].get(0) && !piecesBeforeSubs[k].get(5)) outerBits = 2;
            else if(!piecesBeforeSubs[k].get(0) && piecesBeforeSubs[k].get(5)) outerBits = 1;
            else outerBits = 0;
             
            int innerBits = (int) convertBitsToInteger(reverseOrder(piecesBeforeSubs[k].get(1,5),4));

            piecesAfterSubs[k] = substitutionBox[outerBits][innerBits];     
           
        }

    /**
     * 
     *  Concatenation and Combining
     * 
     */

        for (int m=0; m<12; m++){
            for(int t=0; t<4; t++){
                if(piecesAfterSubs[m].get(t))
                    result.set((m*4)+t);
            }      
        }

        //System.out.println("notper : " + result);


    /**
     * 
     *  Permutation and Swapping
     * 
     */

    for (int c=0; c<48; c++){
        if(c%2 == 0){
            boolean temp = result.get(c);
            result.set(c, result.get(c+1));
            result.set(c+1, temp);
        }
    }
    //System.out.println("scramble  = "+ result);

        return result;
    }



    /** 
    * converts BitSets into Integer values. 
    */

    public static long convertBitsToInteger(BitSet bits) 
    {      
        long value = 0L;
        for (int i = 0; i < bits.length(); ++i) {
          value += bits.get(i) ? (1L << i) : 0L;
        }
        return value;
      }

    /** 
    * reverses the order of BitSets.
    */

    public static BitSet reverseOrder(BitSet bitset, int length) 
    {
        if (length == 2){
            if(bitset.get(0)){
                if(!bitset.get(1)){
                    bitset.clear();
                    bitset.set(1);
                }
            }else{
                if(bitset.get(1)){
                    bitset.clear();
                    bitset.set(0);
                }
            }
        }
        else if(length == 4){
            int firstElement = 0; int secondElement = 0; int thirdElement = 0; int fourthElement = 0; 
            if(bitset.get(0)) firstElement = 1; if(bitset.get(1)) secondElement = 1;
            if(bitset.get(2)) thirdElement = 1; if(bitset.get(3)) fourthElement = 1;
            bitset.clear();
            if(firstElement == 1) bitset.set(3); if(secondElement == 1) bitset.set(2);
            if(thirdElement == 1) bitset.set(1); if(fourthElement == 1) bitset.set(0);
        }

        return bitset;
    }

    /**
     * reads the key from file and converts it from Base64 to binary
     * 
     * @throws IOException
     */
    private void readKey(String keyFile) throws IOException
    {
        BufferedReader br = new BufferedReader(new FileReader(keyFile));

        String line;
        StringBuilder keySB = new StringBuilder();
        // reads all the key text and stores updates temporary string builder object
        while ((line = br.readLine()) != null)
            keySB.append(line);

        br.close();

        String keyStr = keySB.toString();
         
        Decoder decoder = Base64.getDecoder();
        byte[] bytes = decoder.decode(keyStr.getBytes(StandardCharsets.UTF_8));
        keyStr = new String(bytes, StandardCharsets.UTF_8);


        for (int i = 0; i < 96; i++)
        {
            if (keyStr.charAt(i) == '1')
                key.set(i);
        }

    }



    // reads text (cipher/plain) from the input file and stores it
    private void readText(String f, boolean isPlain) throws IOException
    {
        BufferedReader br = new BufferedReader(new FileReader(f));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = br.readLine()) != null)
            sb.append(line);
        br.close();

        int len = sb.length();
        // if ciphertext is not multiple of 96, it adds zeros to the end of the text
        if (len%96 != 0)
        {
            int loop = 96 - (len%96);
            for (int i = 0; i < loop; i++)
                sb.append("0"); // add 0 to the end of the text
        }
        textLen = sb.length();

        BitSet bt = new BitSet();

        for (int i = 0; i < textLen; i++)
        {
            if (sb.charAt(i) == '1')
                bt.set(i);
        }

        // assigns the modified bitset object according to boolean isPlain
        if (isPlain)
            plainT = (BitSet) bt.clone();
        else
            cipherT = (BitSet) bt.clone();
        
    }

    /**
     *  writes to the output file by use of buffered writer
     */
    private static void writeOutFile(BitSet data)
    {
        try {
            BufferedWriter bw = new BufferedWriter(new FileWriter(outFile));
            bw.write("");
            bw.close();

            bw = new BufferedWriter(new FileWriter(outFile, true));

            // write data to file
            for (int i = 0; i < textLen; i++)
            {
                if (data.get(i))
                    bw.write("1");
                else
                    bw.write("0");
            }

            // close the writer
            bw.close();
        
        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }
    
    
}