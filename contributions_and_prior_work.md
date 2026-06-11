# DLTF: What Is Derived from Prior Work and What Is Novel

## Derived from prior work

**Hardware identity machinery.** The enrollment protocol implements standard TPM 2.0
mechanisms defined by the Trusted Computing Group: the Endorsement Key (EK) as a
device-bound identity, EK certificates as manufacturer-issued proof of genuine
silicon, and the MakeCredential/ActivateCredential exchange as proof that a client
holds an EK inside a real TPM. None of this cryptography is ours; we apply it.

**Detection.** The gradient filter composes four established techniques: norm
clipping against the median (scaling attacks), cosine deviation from a robust
median reference (targeted poisoning, in the spirit of Krum, Blanchard et al.
2017), sustained pairwise-similarity detection of colluding clients (a simplified
variant of FoolsGold, Fung et al. 2020), and temporal self-consistency for sleeper
agents. Detection is deliberately not claimed as a contribution.

**Reputation structure.** The score-threshold-status pattern follows P2P trust
systems (EigenTrust, Kamvar et al. 2003; PeerTrust, Xiong & Liu 2004) and
reputation-weighted federated aggregation (Kang et al. 2019). Three design
principles are imported from the literature: graduated sanctions (Ostrom 1990),
asymmetric trust dynamics, where trust is lost faster than it is regained
(Slovic 1993; CONFIDANT, Buchegger & Le Boudec 2002), and the result that
sanctions are meaningless when pseudonyms are free (Friedman & Resnick 2001),
which is the theoretical backbone of this thesis.

**Learning substrate.** FedAvg, Krum, and trimmed-mean aggregation, a standard
CNN on MNIST, and conventional non-IID partitioning are all textbook components.

## Novel in this work

1. **Tier-coupled sanction policy.** Existing reputation systems apply one policy
to all clients. DLTF indexes the entire policy table, including weight cap, strikes
before sanction, and rehabilitation eligibility, on the *measured replacement cost
of the client's identity* (hardware-certified, TPM-resident, or software). Policy
as a function of identity cost has, to our knowledge, no precedent.

2. **Hardware-persistent negative reputation.** Bans bind to the EK hash, so a
banned device is recognized at re-enrollment regardless of its claimed name.
Prior systems can only make good reputation slow to earn; ours makes bad
reputation impossible to shed without purchasing new certified hardware,
converting whitewashing from free to hardware-cost-bound.

3. **A rehabilitation lifecycle.** Sanctioned Tier-1 devices enter probation in
which only their own updates train an isolated shadow model; reinstatement
requires a positive accuracy slope over an HMAC-randomized window, with a
one-shot extension and permanent ban otherwise. "Recovery" in the FL literature
means rolling back the model; client rehabilitation does not previously exist,
and it is only safe because of contribution 2.

4. **Quantified attacker cost.** The evaluation prices trust empirically: a
persistent attacker buys ~0.91 weight-rounds per Tier-1 identity at the cost of a
physical TPM, versus ~0.02 per free Tier-2 identity, while the defense is shown
to cost nothing in the attack-free case.

The contribution is therefore a systems composition: known identity primitives
and known detectors, joined by a novel sanction-and-rehabilitation policy rooted
in hardware identity cost.

## References

[1] Trusted Computing Group, "Trusted Platform Module Library Specification,
Family 2.0," TCG, 2019.

[2] P. Blanchard, E. M. El Mhamdi, R. Guerraoui, and J. Stainer, "Machine
Learning with Adversaries: Byzantine Tolerant Gradient Descent," in *Advances in
Neural Information Processing Systems (NeurIPS)*, 2017.

[3] C. Fung, C. J. M. Yoon, and I. Beschastnikh, "The Limitations of Federated
Learning in Sybil Settings," in *Proc. 23rd International Symposium on Research
in Attacks, Intrusions and Defenses (RAID)*, 2020.

[4] S. D. Kamvar, M. T. Schlosser, and H. Garcia-Molina, "The EigenTrust
Algorithm for Reputation Management in P2P Networks," in *Proc. 12th
International World Wide Web Conference (WWW)*, 2003.

[5] L. Xiong and L. Liu, "PeerTrust: Supporting Reputation-Based Trust for
Peer-to-Peer Electronic Communities," *IEEE Transactions on Knowledge and Data
Engineering*, vol. 16, no. 7, 2004.

[6] J. Kang, Z. Xiong, D. Niyato, S. Xie, and J. Zhang, "Incentive Mechanism for
Reliable Federated Learning: A Joint Optimization Approach to Combining
Reputation and Contract Theory," *IEEE Internet of Things Journal*, vol. 6,
no. 6, 2019.

[7] E. Ostrom, *Governing the Commons: The Evolution of Institutions for
Collective Action*. Cambridge University Press, 1990.

[8] P. Slovic, "Perceived Risk, Trust, and Democracy," *Risk Analysis*, vol. 13,
no. 6, 1993.

[9] S. Buchegger and J.-Y. Le Boudec, "Performance Analysis of the CONFIDANT
Protocol (Cooperation Of Nodes: Fairness In Dynamic Ad-hoc NeTworks)," in
*Proc. ACM MobiHoc*, 2002.

[10] E. Friedman and P. Resnick, "The Social Cost of Cheap Pseudonyms,"
*Journal of Economics & Management Strategy*, vol. 10, no. 2, 2001.

[11] H. B. McMahan, E. Moore, D. Ramage, S. Hampson, and B. Agüera y Arcas,
"Communication-Efficient Learning of Deep Networks from Decentralized Data," in
*Proc. 20th International Conference on Artificial Intelligence and Statistics
(AISTATS)*, 2017.

[12] D. Yin, Y. Chen, R. Kannan, and P. Bartlett, "Byzantine-Robust Distributed
Learning: Towards Optimal Statistical Rates," in *Proc. 35th International
Conference on Machine Learning (ICML)*, 2018.
