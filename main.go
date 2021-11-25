package main

import (
  "fmt"
  "encoding/json"
  "math/big"
  "math/rand"
  poly "github.com/georgercarder/polynomial"
  fs "github.com/georgercarder/ip-sesh/common" // to use file utilities
  kzg "github.com/arnaucube/kzg-commitments-study"
  gthCrypto "github.com/ethereum/go-ethereum/crypto"
)

type DataPoint struct {
  Filename string
  Idx int
  Data byte
}

func Slice2Int64(slc []byte) (r int64) {
  b := new(big.Int)
  b.SetBytes(slc)
  r = b.Int64()
  return
}

func main() {

  //////////////// commiting to private data

  // read file
  exampleFilename := "./data/cat_noms_corn.jpg"
  data, err := fs.SafeFileRead(exampleFilename)
  if err != nil {
    panic(err)
  }

  // form random index array for sampling
  var filenameAndData []byte
  filenameAndData = append(filenameAndData, []byte(exampleFilename)...)
  filenameAndData = append(filenameAndData, data...)
  seedHash := gthCrypto.Keccak256(filenameAndData)
  rand.Seed(Slice2Int64(seedHash))
  var randIdxArray []int
  numSamplePoints := 100
  for i:=0; i<numSamplePoints; i++ {
    randIdxArray = append(randIdxArray, rand.Int()%len(data))
  }
  
  // hash all points {filename, idx, data[idx]} for the sampled idx
  var roots []*big.Int
  rootsCH := make(chan *big.Int)
  for _, idx := range randIdxArray {
    go func(i int) {
      p := data[i]
      dp := &DataPoint{Filename: exampleFilename,
                       Idx: i,
                       Data: p}
      marshalled, _ := json.Marshal(dp) // no err will happen :)
      hash := gthCrypto.Keccak256(marshalled)
      bHash := new(big.Int).SetBytes(hash)
      rootsCH <- bHash
    }(idx)
  }
  // empty channel
  for i:=0;i<len(randIdxArray); i++ {
    roots = append(roots, <-rootsCH)
  }

  // form polynomial
  p := poly.NewPolynomialWithRootsFromArray(roots) // 1000 roots takes about 10G ram 

  // commit to polynomial
  ts, err := kzg.NewTrustedSetup(len(p.Coefficients))
  if err != nil {
    panic(err)
  }

  c := kzg.Commit(ts, p.Coefficients)
  fmt.Println("debug c", c)


  //////////////// below proving and verifying possession

  // sample points, prove, and verify possession
  sampleIdx := randIdxArray[42]
  dp := &DataPoint{Filename: exampleFilename,
                   Idx: sampleIdx,
                   Data: data[sampleIdx]}
  fmt.Println("debug sample dp", dp)
  marshalled, _ := json.Marshal(dp) // no err will happen :)
  hash := gthCrypto.Keccak256(marshalled)
  bHash := new(big.Int).SetBytes(hash)
  
  z:=bHash
  y:=big.NewInt(0) // bHash is a root :)

  proof, err := kzg.EvaluationProof(ts, p.Coefficients, z, y)
  if err != nil {
    panic(err)
  }

  v := kzg.Verify(ts, c, proof, z, y)
  fmt.Println("debug v", v)
  if v != true {
    panic("NOT VERIFIED")
  }
}
