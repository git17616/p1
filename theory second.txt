theory second
begin 

builtins: hashing, bilinear-pairing, xor

functions:h/1


rule Setup:
    let
        pkA = 'g'^~xA
        skA = h('A')^~xA
        pkB = 'g'^~xB
        skB = h('B')^~xB
    in
    [Fr(~xA),
    Fr(~xB)]
    --[OnlyOnceV('Setup')]->
    [!LtkC($Client, skA, ~xA,'A', pkA),
    !LtkS($Server, skB, ~xB,'B', pkB),
    Out(< 'A', pkA,'B', pkB>)]

rule Client_1:
let 
    V1 = 'g'^~e1
    V2 = pkB^~e1
    rA = em(skA, pkB)^~e1
    VA = h(<V1,rA>)
    UA = <VA*skA, ~e1*skA>
    V3 = id_Client XOR h(<V2,id_Server>)
    V4 = h(<V2, rA, id_Client, ~t1>)

in
[
    !LtkC($Client, skA, ~xA, id_Client,pkA), 
    In(<id_Server, pkB>),
    Fr(~e1),
    Fr(~t1)
]-->[
    Out(<V1,~t1, VA, UA, V3, V4>),
    StoreA(~e1, ~t1, skA, ~xA, VA, pkA)
]

rule Server_1:
let 
    V21 = V1 ^~xB
    idA1 = V3 XOR h(<V21, 'B'>) 
    ra =em(UA, pkB)*em(h('A')^~xB, pkA)^VA
    V41 = h(<V21,ra,idA1,~t1>)

    C1 = 'g'^~e2
    rB = em(skB,pkA)^~e2
    VB = h(<C1,rB>)
    UB = <VB*skB, ~e2*skB>

    skB1 = ra^(~e1*inv(~xB))
    skB2 = em(skB,V1)^~e2
    skB3 = V1^~e2
    skS = h(<skB1,skB2,skB3>)

    C2 = h(<skS,skB3>)
    Auth1 = h(<VA, VB, C2, ~t1, ~t2>)
    Auth4 = h(<VA, VB, skS, ~t1, ~t2>)

in
[!LtkS($Server, skB, ~xB,id_Server, pkB),
 In(<V1,~t1, VA, UA, V3, V4>),
 In(<id_Client, pkA>),
 Fr(~e2),
 Fr(~t2)
]
--[Eq(id_Client,'A'),Eq(V4,V41)]->
[ Out(<C1, VB, UB, Auth1, ~t2>), StoreB(~t2,Auth4)]

rule Client_2:
let 
    rb = em(UB, pkA)*em(h('B')^~xA, pkB)^VB

    skA1 = em(skA,C1)^~e1
    skA2 = rb^(~e1*inv(~xA))
    skA3 = C1^~e1
    skC = h(<skA2,skA1,skA3>)
    
    V5 = h(<skA3,skC>) 
 
    Auth2 = h(<VA,VB,V5, ~t1, ~t2>)
    Auth3 = h(<VA,VB, skC, ~t1, ~t2>)
in
[StoreA(~e1, ~t1, skA, ~xA, VA, pkA),
 !LtkC($Client, skA, ~xA,id_Client, pkA),
 In(<C1,VB, UB, Auth1, ~t2>),
 In(<id_Server, pkB>)
]-->[
    Out(Auth3)
 ]

rule Server_2:
[In(Auth3), StoreB(~t2,Auth4)]--[Eq(Auth4,Auth3)]->[]

restriction OnlyOnceV:
"All #i #j x. OnlyOnceV(x)@#i & OnlyOnceV(x)@#j ==> #i = #j"

restriction Equality:
"All x y #i. Eq(x,y) @#i ==> x = y"
end

