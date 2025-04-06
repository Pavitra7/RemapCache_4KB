/*
 *  cache,Memory.h
 *
 *  Created on: 15 févr. 2019 / new version July 2021
 *      Author: simon + logan
 */

#ifndef INCLUDE_CACHEMEMORY_H_
#define INCLUDE_CACHEMEMORY_H_

#include <ac_int.h>
#include <logarithm.h>
#include <memoryInterface.h>
#include <time.h>

/************************************************************************
 * 	Following values are templates:
 * 		- OFFSET_SIZE
 * 		- TAG_SIZE
 * 		- SET_SIZE
 * 		- ASSOCIATIVITY
 ************************************************************************/
template <unsigned int INTERFACE_SIZE, int LINE_SIZE, int SET_SIZE>
class CacheMemory : public MemoryInterface<INTERFACE_SIZE> {

  static const int LOG_SET_SIZE           = log2const<SET_SIZE>::value;
  static const int LOG_LINE_SIZE          = log2const<LINE_SIZE>::value;
  static const int TAG_SIZE               = (32 - LOG_LINE_SIZE - LOG_SET_SIZE);
  static const int ASSOCIATIVITY          = 4;
  static const int LOG_ASSOCIATIVITY      = 2;
  static const int STATE_CACHE_MISS       = ((LINE_SIZE / INTERFACE_SIZE) * 2 + 2);
  static const int STATE_CACHE_LAST_STORE = ((LINE_SIZE / INTERFACE_SIZE) + 3);
  static const int STATE_CACHE_FIRST_LOAD = ((LINE_SIZE / INTERFACE_SIZE) + 2);
  static const int STATE_CACHE_LAST_LOAD  = 2;
  static const int LOG_INTERFACE_SIZE     = log2const<INTERFACE_SIZE>::value;
  int key			   = 5;

public:
  
  IncompleteMemory<INTERFACE_SIZE>* nextLevel;

  ac_int<TAG_SIZE + LINE_SIZE * 8, false> cacheMemory[SET_SIZE][ASSOCIATIVITY];
  ac_int<40, false> age[SET_SIZE][ASSOCIATIVITY];
  ac_int<1, false> dataValid[SET_SIZE][ASSOCIATIVITY];
  ac_int<1, false> dirtyBit[SET_SIZE][ASSOCIATIVITY];		
  ac_int<1,false> secretBit[SET_SIZE][ASSOCIATIVITY];		// one bit per line for secret marking
  ac_int<1,false> remapBit[SET_SIZE][ASSOCIATIVITY];			//one bit per line for remaped on encryption
  ac_int<6, false> cacheState;// Used for the internal state machine
  
// Variables for next level access
  ac_int<LINE_SIZE * 8 + TAG_SIZE, false> newVal, oldVal;
  ac_int<32, false> nextLevelAddr;
  memOpType nextLevelOpType;
  ac_int<INTERFACE_SIZE * 8, false> nextLevelDataIn;
  ac_int<INTERFACE_SIZE * 8, false> nextLevelDataOut;
  ac_int<40, false> cycle;
  ac_int<LOG_ASSOCIATIVITY, false> setMiss;
  bool isValid;
  bool isDirty;
  clock_t start, end;
  bool wasStore = false;
  ac_int<LOG_ASSOCIATIVITY, false> setStore;
  ac_int<LOG_SET_SIZE, false> placeStore;
  ac_int<LINE_SIZE * 8 + TAG_SIZE, false> valStore;
  ac_int<INTERFACE_SIZE * 8, false> dataOutStore;
  ac_int<1, false> valDirty = 0;

  //clock cycle counter for pavi's experiments
  //This should NOT be synthesized
#ifndef __CATAPULT__
  ac_int<32, false> clockCycleCounter = 0;
  ac_int<8, false> timerCounter = 0xFF;  //for key regeneration
#endif

  bool nextLevelWaitOut;

  bool VERBOSE = false;

  bool addr_superior = false, addr_inferior = false;

  // Stats
  unsigned long numberAccess, numberMiss, secret_counter, curr_sample, prev_miss, curr_miss, ISAT1, ISAT2;		//secret counter counts the cache misses of the secret section

  CacheMemory(IncompleteMemory<INTERFACE_SIZE>* nextLevel, bool v)
  {
    this->nextLevel = nextLevel;
    VERBOSE         = v;
    initCache();
  }

  void initCache()   // initialise every element in a set (one set element) in each set (one set)
  {
    for (int oneSetElement = 0; oneSetElement < SET_SIZE; oneSetElement++) {
      for (int oneSet = 0; oneSet < ASSOCIATIVITY; oneSet++) {
        cacheMemory[oneSetElement][oneSet] = 0;
        age[oneSetElement][oneSet]         = ac_int<40, false>(0);
        dataValid[oneSetElement][oneSet]   = 0;
        dirtyBit[oneSetElement][oneSet]    = 0;
        secretBit[oneSetElement][oneSet]   = 0;   //each set element has a seperate bit to mark secrets
        remapBit[oneSetElement][oneSet]    = 0;   //each set element has a seperate bit to mark encrypted remapped address
        
        //printf("Cache initialised");
      }
    }
    numberAccess     = 0;
    numberMiss       = 0;
    nextLevelWaitOut = false;
    wasStore         = false;
    cacheState       = 0;
    nextLevelOpType  = NONE;
   // secret_counter   = 0;
   // curr_sample=0;
   // prev_miss=0;
   // curr_miss=0;
   // ISAT1=0;
   // ISAT2=0;
  }

  void process(ac_int<32, false> addr, memMask mask, memOpType opType, ac_int<4, false> hartid,
               ac_int<INTERFACE_SIZE * 8, false> dataIn, ac_int<INTERFACE_SIZE * 8, false>& dataOut, bool& waitOut)
  {
//#ifndef __CATAPULT__
      clockCycleCounter++;
      timerCounter--;
     // printf("Processing address %x \n", (unsigned int)addr);
      //printf("Timer value : %x \n",timerCounter);
      if (timerCounter==0)
      {
      	//printf("Timer reset Time\n");
        key=(key+13) % 100;				//on changing key, reset the remapped locations
        for (int oneSetElement = 0; oneSetElement < SET_SIZE; oneSetElement++) 
          {
            for (int oneSet = 0; oneSet < ASSOCIATIVITY; oneSet++) 
              {// printf("GOING IN LOOP TO CHECK RESET\n");
       	        if(remapBit[oneSetElement][oneSet]==1)
      	           { //printf("Timer reset\n");
      	             remapBit[oneSetElement][oneSet] = 0;
      	             dataValid[oneSetElement][oneSet] = 0;
      	             printf("Remap Reset: Address %x | set: %x | place :%x\n", (unsigned int)addr, oneSetElement, oneSet);
      	             
                    }
      		//printf("Done with refresh");
              }
          }
      }

//#endif
    // bit size is the log(setSize)
    ac_int<LOG_SET_SIZE, false> place = addr.slc<LOG_SET_SIZE>(LOG_LINE_SIZE);
    
    // startAddress is log(lineSize) + log(setSize) + 2
    ac_int<TAG_SIZE, false> tag = addr.slc<TAG_SIZE>(LOG_LINE_SIZE + LOG_SET_SIZE);
    // bitSize is log(lineSize), start address is 2(because of #bytes in a word)
    ac_int<LOG_LINE_SIZE, false> offset = addr.slc<LOG_LINE_SIZE - 2>(2);

    // CLINT
    addr_superior = (addr >= CLINT_BASE);
    addr_inferior = (addr < UART_BASE_ADDR + UART_SIZE);
  
    if (!nextLevelWaitOut) 
      {
        cycle++;
        
	/*if((unsigned int)addr == 0x30b00)    // This is the secret location to be traced
             { //printf("Access at %x\n", (unsigned int)addr);
            ISAT2 = clock();
             ISAT1 = clock()-ISAT1;
             ISAT1 = ISAT2/2;
             
           //  printf("ISAT = %x\n",ISAT2);
          //   printf("ISAT = %x\n",ISAT2);
          }
             */
        if ((wasStore || cacheState == 1 )&& secretBit[placeStore][setStore]==0) 
          {    //if instruction needs to be stored in cache, check if its not a secret location
            cacheMemory[placeStore][setStore] = valStore;				
            age[placeStore][setStore]         = cycle;
            dataValid[placeStore][setStore]   = 1;
            dirtyBit[placeStore][setStore]    = valDirty;
            dataOut                           = dataOutStore;
            wasStore                          = false;
            cacheState                        = 0;
            if (remapBit[placeStore][setStore]==1)			//reset the remap bit as this is normal mapping and not encrypted mapping
              {
        	       remapBit[placeStore][setStore]=0;
       // printf("Remap bit resetted of %x | set: %x | place: %x |\n", (unsigned int)addr, placeStore, setStore);
              }
       // printf("Address stored: %x | set: %x | place: %x |\n", (unsigned int)addr, placeStore, setStore);
       //  printf("Address stored: %x \n", (unsigned int)addr);
            if ((unsigned int)addr == 0x7e764 || (unsigned int)addr == 0x7eef0)
              {
                secretBit[placeStore][setStore]=1;
              //  printf("Secret Address: %x | set: %x | place: %x |\n", (unsigned int)addr, placeStore, setStore);
              
              }
          } 

      else if ((wasStore || cacheState == 1 )&& secretBit[placeStore][setStore]==1)// && (unsigned int)addr !=0x3780)     // if instruction needs to be stored in cache, on a secret location
        {
        //printf("Address: %x | set: %x | place: %x |\n", (unsigned int)addr, placeStore, setStore);
       // printf("SecretBit at location set %x, place %x is %x\n", placeStore, setStore, secretBit[placeStore][setStore]);
        	placeStore=(placeStore * key + b)%SET_SIZE;					// encrypt the location and save
        	setStore = (setStore * key + b)%ASSOCIATIVITY;
          cacheMemory[placeStore][setStore] = valStore;				
          age[placeStore][setStore]         = cycle;
          dataValid[placeStore][setStore]   = 1;
          dirtyBit[placeStore][setStore]    = valDirty;
          dataOut                           = dataOutStore;
          wasStore                          = false;
          cacheState                        = 0;
          remapBit[placeStore][setStore]=1;	
        					                           // since this is encrypted store, set the remap bit
          //if ((unsigned int)addr == 0x3780)
          //  {
             // secretBit[placeStore][setStore]=1;
         //     printf("Remap Address stored: %x | set: %x | place: %x |\n", (unsigned int)addr, placeStore, setStore);
              
            //}
        }
      
      else if (opType != NONE) 
        {

          ac_int<LINE_SIZE * 8 + TAG_SIZE, false> val1 = cacheMemory[place][0];
          ac_int<LINE_SIZE * 8 + TAG_SIZE, false> val2 = cacheMemory[place][1];
          ac_int<LINE_SIZE * 8 + TAG_SIZE, false> val3 = cacheMemory[place][2];
          ac_int<LINE_SIZE * 8 + TAG_SIZE, false> val4 = cacheMemory[place][3];

          ac_int<1, false> valid1 = dataValid[place][0];
          ac_int<1, false> valid2 = dataValid[place][1];
          ac_int<1, false> valid3 = dataValid[place][2];
          ac_int<1, false> valid4 = dataValid[place][3];

          ac_int<16, false> age1 = age[place][0];
          ac_int<16, false> age2 = age[place][1];
          ac_int<16, false> age3 = age[place][2];
          ac_int<16, false> age4 = age[place][3];

          ac_int<1, false> dirty1 = dirtyBit[place][0];
          ac_int<1, false> dirty2 = dirtyBit[place][1];
          ac_int<1, false> dirty3 = dirtyBit[place][2];
          ac_int<1, false> dirty4 = dirtyBit[place][3];

          ac_int<1, false> secret1 = secretBit[place][0];
          ac_int<1, false> secret2 = secretBit[place][1];
          ac_int<1, false> secret3 = secretBit[place][2];
          ac_int<1, false> secret4 = secretBit[place][3];
          
          
         // printf("place : %x\n", place);
          //printf("Remap bits : %x %x %x %x \n", remapBit[place][0],remapBit[place][1],remapBit[place][2],remapBit[place][3]);
          if (cacheState == 0 && addr_superior && addr_inferior) 
            {
              // CLINT - Forward
              nextLevelAddr   = addr;
              nextLevelOpType = opType;
              nextLevelDataIn = dataIn;
              cacheState      = 2; // avoid the first "if" statement
              //printf("** CLINT %x %c **\n", (unsigned int)addr>>2, (char)dataIn);
            } 
          else if (cacheState == 2 && addr_superior && addr_inferior) 
            {
              cacheState      = 0;
              dataOut         = nextLevelDataOut;
              nextLevelOpType = NONE; // avoid a memory call
              //printf("** END_CLINT %x %x **\n", (unsigned int)dataOut, (unsigned int)addr>>2);
            } 
          else if (cacheState == 0) 
            {
              numberAccess++;
            //  printf("Access at %x\n", (unsigned int)addr);
             //printf("Total Cache Access are %d\n",numberAccess);

              ac_int<TAG_SIZE, false> tag1 = val1.template slc<TAG_SIZE>(0);
              ac_int<TAG_SIZE, false> tag2 = val2.template slc<TAG_SIZE>(0);
              ac_int<TAG_SIZE, false> tag3 = val3.template slc<TAG_SIZE>(0);
              ac_int<TAG_SIZE, false> tag4 = val4.template slc<TAG_SIZE>(0);

              bool hit1 = (tag1 == tag) && valid1 ;
              bool hit2 = (tag2 == tag) && valid2 ;
              bool hit3 = (tag3 == tag) && valid3 ;
              bool hit4 = (tag4 == tag) && valid4 ;
              bool hit  = hit1 | hit2 | hit3 | hit4;

              ac_int<LOG_ASSOCIATIVITY, false> set = 0;
              ac_int<LINE_SIZE * 8, false> selectedValue;
              ac_int<TAG_SIZE, false> selectedTag;
              ac_int<1, false> encryptionNeeded;
	             encryptionNeeded=0;
                	//printf("Address search %x | set %x \n", (unsigned int)addr, place);
                //  printf("remap bits at set %x, set0: %x, set1 : %x, set 2: %x, set3 %x\n",place,remap1, remap2,remap3,remap4);
                //printf("Address %x | set: %x | place:%x |\n", (unsigned int)addr, setStore, place);	
                if(secret1 & set==0)
                  {// printf("Address search %x | set %x | place %x |\n", (unsigned int)addr, setStore, place);
               //   printf("remap bits at place %x, set0: %x, set1 : %x, set 2: %x, set3 %x\n",place,remap1, remap2,remap3,remap4);
                    place = (place * key) % SET_SIZE;          // encrypt the location and save
                    setStore = (0 * key) % ASSOCIATIVITY; 
                    
               //     printf("key %x, set_size %x, associativity %x\n",key,SET_SIZE,ASSOCIATIVITY);
                  //  printf("Remap Address search %x | set %x | place %x |\n", (unsigned int)addr, place, setStore);
                    encryptionNeeded=1;
                     
                          
                  }
                  else if(secret2 & set==1)
                  {// printf("Address search %x | set %x | place %x |\n", (unsigned int)addr, setStore, place);
                 // printf("remap bits at place %x, set0: %x, set1 : %x, set 2: %x, set3 %x\n",place,remap1, remap2,remap3,remap4);
                    place=(place * key)%SET_SIZE;          // encrypt the location and save
                    setStore = (1 * key)%ASSOCIATIVITY;  
                    
              //      printf("key %x, set_size %x, associativity %x\n",key,SET_SIZE,ASSOCIATIVITY);
                  //  printf("Remap Address search %x | set %x | place %x |\n", (unsigned int)addr, place, setStore);
                          encryptionNeeded=1; 
                  }
                  else if(secret3 & set==2)
                  { //printf("Address search %x | set %x | place %x |\n", (unsigned int)addr, setStore, place);
                 // printf("remap bits at place %x, set0: %x, set1 : %x, set 2: %x, set3 %x\n",place,remap1, remap2,remap3,remap4);
                    place=(place * key)%SET_SIZE;          // encrypt the location and save
                    setStore = (2 * key)%ASSOCIATIVITY;  
                   
                //    printf("key %x, set_size %x, associativity %x\n",key,SET_SIZE,ASSOCIATIVITY);
                    printf("Remap Address search %x | set %x | place %x |\n", (unsigned int)addr, place, setStore);
                           encryptionNeeded=1; 
                  }
                  else if(secret4 & set==3)
                  { //printf("Address search %x | set %x | place %x |\n", (unsigned int)addr, setStore, place);
                //  printf("remap bits at place %x, set0: %x, set1 : %x, set 2: %x, set3 %x\n",place,remap1, remap2,remap3,remap4);
                    place=(place * key)%SET_SIZE;          // encrypt the location and save
                    setStore = (3 * key)%ASSOCIATIVITY;  
                   
                    //printf("key %x, set_size %x, associativity %x\n",key,SET_SIZE,ASSOCIATIVITY);
                   // printf("Remap Address search %x | set %x \n", (unsigned int)addr, place);
                           encryptionNeeded=1; 
                  }
                  
                
    if(encryptionNeeded){          
              val1 = cacheMemory[place][0];
         val2 = cacheMemory[place][1];
          val3 = cacheMemory[place][2];
          val4 = cacheMemory[place][3];

          valid1 = dataValid[place][0];
          valid2 = dataValid[place][1];
          valid3 = dataValid[place][2];
          valid4 = dataValid[place][3];

          age1 = age[place][0];
         age2 = age[place][1];
          age3 = age[place][2];
         age4 = age[place][3];

          dirty1 = dirtyBit[place][0];
          dirty2 = dirtyBit[place][1];
          dirty3 = dirtyBit[place][2];
          dirty4 = dirtyBit[place][3];
          
          ac_int<1, false> remap1 = remapBit[place][0];
          ac_int<1, false> remap2 = remapBit[place][1];
          ac_int<1, false> remap3 = remapBit[place][2];
          ac_int<1, false> remap4 = remapBit[place][3];
          
          //if(remap1| remap2 | remap3 |remap4)
                	//{
                		//encryptionNeeded=1;
                	//}
                	//else
                	//encryptionNeeded=0; 
                	
                	
          hit1 = (tag1 == tag) && valid1 && remap1;
              hit2 = (tag2 == tag) && valid2 && remap2 ;
              hit3 = (tag3 == tag) && valid3 && remap3;
              hit4 = (tag4 == tag) && valid4 && remap4;
              hit  = hit1 | hit2 | hit3 | hit4;  
          
                if (hit1 ) 
                {
                  selectedValue = val1.template slc<LINE_SIZE * 8>(TAG_SIZE);
                  selectedTag           = tag1;
                  set           = 0;
                  //printf("remap Hit Address %x | set: %x | place:%x | remap 0\n", (unsigned int)addr, place, set);
                }

                if (hit2) 
                {
                  selectedValue = val2.template slc<LINE_SIZE * 8>(TAG_SIZE);
                  selectedTag           = tag2;
                  set           = 1;
                 //  printf("remap Hit Address %x | set: %x | place:%x | remap 1\n", (unsigned int)addr, place, set);
                }

                if (hit3) 
                {
                  selectedValue = val3.template slc<LINE_SIZE * 8>(TAG_SIZE);
                  selectedTag           = tag3;
                  set           = 2;
                 // printf("remap Hit Address %x | set: %x | place:%x | remap 2\n", (unsigned int)addr, place, set);
                }

                if (hit4) 
                {
                  selectedValue = val4.template slc<LINE_SIZE * 8>(TAG_SIZE);
                  selectedTag           = tag4;
                  set           = 3;
                   //printf("remap Hit Address %x | set: %x | place:%x | remap 3\n", (unsigned int)addr, place, set);
                }
                
                if(hit)
                {printf("remap Hit Address %x | set: %x | place:%x | remap 3\n", (unsigned int)addr, place, set);
                }
                else 
                {
                printf("Final Miss \n");}
                
}
else
{

              hit1 = (tag1 == tag) && valid1 ;
              hit2 = (tag2 == tag) && valid2 ;
              hit3 = (tag3 == tag) && valid3 ;
              hit4 = (tag4 == tag) && valid4 ;
              hit  = hit1 | hit2 | hit3 | hit4;  
if (hit1) 
                {
                  selectedValue = val1.template slc<LINE_SIZE * 8>(TAG_SIZE);
                  selectedTag           = tag1;
                  set           = 0;
                }

                if (hit2) 
                {
                  selectedValue = val2.template slc<LINE_SIZE * 8>(TAG_SIZE);
                  selectedTag           = tag2;
                  set           = 1;
                }

                if (hit3) 
                {
                  selectedValue = val3.template slc<LINE_SIZE * 8>(TAG_SIZE);
                  selectedTag           = tag3;
                  set           = 2;
                }

                if (hit4) 
                {
                  selectedValue = val4.template slc<LINE_SIZE * 8>(TAG_SIZE);
                  selectedTag           = tag4;
                  set           = 3;
                }


}
            ac_int<8, true> signedByte;
            ac_int<16, true> signedHalf;
            ac_int<32, true> signedWord;

          if (hit) 
          { printf("Hit Address %x | set: %x | place:%x |\n", (unsigned int)addr, place, set);
            ac_int<LINE_SIZE * 8 + TAG_SIZE, false> localValStore = 0;
            localValStore.set_slc(TAG_SIZE, selectedValue);
            localValStore.set_slc(0, selectedTag);
            
#ifndef __CATAPULT__
          //  std::cout << std::endl << "HitMEMTRACE, cache hit: " << clockCycleCounter << ", " << addr << std::endl; 
#endif
            // First we handle the store
            if (opType == STORE) 
            {
              switch (mask) 
              {
                case BYTE:
                case BYTE_U:
                  localValStore.set_slc((((int)addr.slc<2>(0)) << 3) + TAG_SIZE + 4 * 8 * offset,
                                        dataIn.template slc<8>(0));
                  break;
                case HALF:
                case HALF_U:
                  localValStore.set_slc((addr[1] ? 16 : 0) + TAG_SIZE + 4 * 8 * offset, dataIn.template slc<16>(0));
                  break;
                case WORD:
                  localValStore.set_slc(TAG_SIZE + 4 * 8 * offset, dataIn.template slc<32>(0));
                  break;
                case LONG:
                  localValStore.set_slc(TAG_SIZE + 4 * 8 * offset, dataIn);
                  break;
              }

              placeStore = place;
              setStore   = set;
              valStore   = localValStore;
              valDirty   = 1;
              wasStore   = true;

            }
           
            
            
            
            
            
            
            
            else {
            
              switch (mask) {
                case BYTE:
                  signedByte = selectedValue.template slc<8>((((int)addr.slc<2>(0)) << 3) + 4 * 8 * offset);
                  signedWord = signedByte;
                  dataOut.set_slc(0, signedWord);
                  break;
                case HALF:
                  signedHalf = selectedValue.template slc<16>((addr[1] ? 16 : 0) + 4 * 8 * offset);
                  signedWord = signedHalf;
                  dataOut.set_slc(0, signedWord);
                  break;
                case WORD:
                  dataOut = selectedValue.template slc<32>(4 * 8 * offset);
                  break;
                case BYTE_U:
                  dataOut = selectedValue.template slc<8>((((int)addr.slc<2>(0)) << 3) + 4 * 8 * offset) & 0xff;
                  break;
                case HALF_U:
                  dataOut = selectedValue.template slc<16>((addr[1] ? 16 : 0) + 4 * 8 * offset) & 0xffff;
                  break;
                case LONG:
                  dataOut = selectedValue.template slc<INTERFACE_SIZE * 8>(4 * 8 * offset);
                  break;
              }
	   	//if((unsigned int)addr >= 0x246d4 && (unsigned int)addr <= 0x24b4a)    // This is the secret location to be traced
              //printf("Hit read %x at %x\n", (unsigned int)dataOut, (unsigned int)addr);
             
              //printf("time is at %x\n",clock());

            }
            // age[place][set] = cycle;

          }
          
       
          
          
          
          
          else {						// Miss happened
            numberMiss++;
            //printf("Miss\n");
            printf("Miss Address %x set: %x \n", (unsigned int)addr, place);
           // printf("Address that caused miss %x\n", (unsigned int)addr);
	   // if((unsigned int)addr == 0x5629f3f40475)
	   // {
	    //	printf("Secret Miss Happening at %x", (unsigned int)addr);
	   // }
#ifndef __CATAPULT__
           // std::cout << std::endl << "MEMTRACE, cache miss: " << clockCycleCounter << ", " << addr << std::endl; 
#endif
           //printf("Total Cache numberMiss are %d\n",numberMiss);
            cacheState = STATE_CACHE_MISS;
          }
        } else {
          
//printf("Miss %d\n", (unsigned int)cacheState);
          if (cacheState == STATE_CACHE_MISS) {
            newVal  = tag;
            setMiss = (age1 <= age2 && age1 <= age3 && age1 <= age4)
                          ? 0
                          : ((age2 <= age1 && age2 <= age3 && age2 <= age4)
                                 ? 1
                                 : ((age3 <= age2 && age3 <= age1 && age3 <= age4) ? 2 : 3));
            oldVal = (age1 <= age2 && age1 <= age3 && age1 <= age4)
                         ? val1
                         : ((age2 <= age1 && age2 <= age3 && age2 <= age4)
                                ? val2
                                : ((age3 <= age2 && age3 <= age1 && age3 <= age4) ? val3 : val4));
            isValid = (age1 <= age2 && age1 <= age3 && age1 <= age4)
                          ? valid1
                          : ((age2 <= age1 && age2 <= age3 && age2 <= age4)
                                 ? valid2
                                 : ((age3 <= age2 && age3 <= age1 && age3 <= age4) ? valid3 : valid4));
            isDirty = (age1 <= age2 && age1 <= age3 && age1 <= age4)
                          ? dirty1
                          : ((age2 <= age1 && age2 <= age3 && age2 <= age4)
                                 ? dirty2
                                 : ((age3 <= age2 && age3 <= age1 && age3 <= age4) ? dirty3 : dirty4));
            if (isDirty == 0) {
              cacheState = STATE_CACHE_LAST_STORE - 1;
            }
             //printf("TAG is %x\n", oldVal.slc<TAG_SIZE>(0));
          }

          ac_int<32, false> oldAddress = (((int)oldVal.template slc<TAG_SIZE>(0)) << (LOG_LINE_SIZE + LOG_SET_SIZE)) |
                                         (((int)place) << LOG_LINE_SIZE);
          // First we write back the four memory values in upper level

          if (cacheState >= STATE_CACHE_LAST_STORE) {
            // We store all values into next memory interface
            nextLevelAddr   = oldAddress + (((int)(cacheState - STATE_CACHE_LAST_STORE)) << LOG_INTERFACE_SIZE);
            nextLevelDataIn = oldVal.template slc<INTERFACE_SIZE * 8>(
                (cacheState - STATE_CACHE_LAST_STORE) * INTERFACE_SIZE * 8 + TAG_SIZE);
            nextLevelOpType = (isValid) ? STORE : NONE;

             //printf("Writing back %x %x at %x\n", (unsigned
            // int)nextLevelDataIn.slc<32>(0),
              //     (unsigned int)nextLevelDataIn.slc<32>(32), (unsigned
                //    int)nextLevelAddr);

          } else if (cacheState >= STATE_CACHE_LAST_LOAD) {
            // Then we read values from next memory level
            if (cacheState != STATE_CACHE_FIRST_LOAD) {
              newVal.set_slc(((unsigned int)(cacheState - STATE_CACHE_LAST_LOAD)) * INTERFACE_SIZE * 8 + TAG_SIZE,
                             nextLevelDataOut); // at addr +1
            }

            if (cacheState != STATE_CACHE_LAST_LOAD) {
              // We initiate the load at the address determined by next cache
              // state
              nextLevelAddr = (((int)addr.slc<32 - LOG_LINE_SIZE>(LOG_LINE_SIZE)) << LOG_LINE_SIZE) +
                              ((cacheState - STATE_CACHE_LAST_LOAD - 1) << LOG_INTERFACE_SIZE);
              nextLevelOpType = LOAD;
            }
          }

          cacheState--;

          if (cacheState == 1) {
            valDirty = 0;
            if (opType == STORE) {
              switch (mask) {
                case BYTE:
                case BYTE_U:
                  newVal.set_slc((((int)addr.slc<2>(0)) << 3) + TAG_SIZE + 4 * 8 * offset, dataIn.template slc<8>(0));
                  break;
                case HALF:
                case HALF_U:
                  newVal.set_slc((addr[1] ? 16 : 0) + TAG_SIZE + 4 * 8 * offset, dataIn.template slc<16>(0));
                  break;
                case WORD:
                  newVal.set_slc(TAG_SIZE + 4 * 8 * offset, dataIn.template slc<32>(0));
                  break;
                case LONG:
                  newVal.set_slc(TAG_SIZE + 4 * 8 * offset, dataIn);
                  break;
              }
              valDirty = 1;
            }

     // Step 1: Compute modular inverse of a mod m using Extended Euclidean Algorithm
    int m0 = SET_SIZE;
    int x0 = 0, x1 = 1;
    int q, t;

    int a_copy = a;
    int m_copy = m;

    while (m_copy > 1) {
        q = a_copy / m_copy;

        t = m_copy;
        m_copy = a_copy % m_copy;
        a_copy = t;

        t = x0;
        x0 = x1 - q * x0;
        x1 = t;
    }

    if (x1 < 0)
        x1 += m0;

    int a_inv = x1;

    // Step 2: Reverse the hash: x = ((h - b) * a_inv) % m
    ac_int<32, false> addr_old = (a_inv * ((h - b + m) % m)) % m;
ac_int<LOG_SET_SIZE, false> place_old = addr_old.slc<LOG_SET_SIZE>(LOG_LINE_SIZE);
   
    return 0;

            placeStore = place;
            setStore   = setMiss;
            valStore   = newVal;

            nextLevelOpType = NONE;

            ac_int<8, true> signedByte;
            ac_int<16, true> signedHalf;
            ac_int<32, true> signedWord;

            switch (mask) {
              case BYTE:
                signedByte = newVal.template slc<8>((((int)addr.slc<2>(0)) << 3) + 4 * 8 * offset + TAG_SIZE);
                signedWord = signedByte;
                dataOut.set_slc(0, signedWord);
                break;
              case HALF:
                signedHalf = newVal.template slc<16>((addr[1] ? 16 : 0) + 4 * 8 * offset + TAG_SIZE);
                signedWord = signedHalf;
                dataOut.set_slc(0, signedWord);
                break;
              case WORD:
                dataOut = newVal.template slc<32>(4 * 8 * offset + TAG_SIZE);
                break;
              case BYTE_U:
                dataOut = newVal.template slc<8>((((int)addr.slc<2>(0)) << 3) + 4 * 8 * offset + TAG_SIZE) & 0xff;
                break;
              case HALF_U:
                dataOut = newVal.template slc<16>((addr[1] ? 16 : 0) + 4 * 8 * offset + TAG_SIZE) & 0xffff;
                break;
              case LONG:
                dataOut = newVal.template slc<INTERFACE_SIZE * 8>(4 * 8 * offset);
                break;
            }
          //   printf("After Miss read %x at %x\n", (unsigned
           //  int)dataOut.slc<32>(0), (unsigned int)addr);

            dataOutStore = dataOut;
          }
        }
      }
    };
    this->nextLevel->process(nextLevelAddr, WORD, nextLevelOpType, hartid, nextLevelDataIn, nextLevelDataOut,
                             nextLevelWaitOut);
    waitOut = nextLevelWaitOut || cacheState || wasStore;
  }
};

#endif /* INCLUDE_CACHEMEMORY_H_ */
