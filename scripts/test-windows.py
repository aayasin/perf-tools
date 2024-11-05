import analyze as A
import common as C
A.setup('blender_barbershop_arls_baseline', 'blender_barbershop_arls_baseline-janysave_type-eBR_INST_RETIRED.NEAR_TAKENpdir-c4000003.perf.data')
A.threshold['misp-sig-ifetch'] = 0.3
C.printc("A.analyze_misp()")
A.analyze_misp()
C.printc("A.analyze_ifetch()")
A.analyze_ifetch()
