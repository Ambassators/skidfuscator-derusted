package org.mapleir.ir.cfg.builder.ssaopt;

import org.mapleir.ir.code.Expr;
import org.mapleir.ir.code.Opcode;

public class ConstraintUtil implements Opcode {

	public static boolean isInvoke(/*Expr e*/ int opcode) {
		// int opcode = e.getOpcode();
		/* INIT_OBJ contains a folded constructor call. */
		return opcode == INVOKE || opcode == INIT_OBJ;
	}

	public static boolean isUncopyable(Expr e) {
		for(Expr c : e.enumerateWithSelf()) {
			int op = c.getOpcode();
            // A Java expression can throw or initialize a class even when its
            // produced value is unused. Never duplicate/drop such evaluations.
            boolean arithmeticException = c instanceof org.mapleir.ir.code.expr.ArithmeticExpr
                    && (((org.mapleir.ir.code.expr.ArithmeticExpr) c).getOperator()
                            == org.mapleir.ir.code.expr.ArithmeticExpr.Operator.DIV
                        || ((org.mapleir.ir.code.expr.ArithmeticExpr) c).getOperator()
                            == org.mapleir.ir.code.expr.ArithmeticExpr.Operator.REM);
            if (isUncopyable0(op) || arithmeticException) {
				return true;
			}
		}
		return false;
	}
	
	private static boolean isUncopyable0(int opcode) {
		switch (opcode) {
			case INVOKE:
			case INIT_OBJ:
			case ALLOC_OBJ:
			case NEW_ARRAY:
            case ARRAY_LEN:
            case ARRAY_LOAD:
            case FIELD_LOAD:
            case CAST:
            case INSTANCEOF:
			case CATCH:
			case EPHI:
			case PHI:
				return true;
		};
		return false;
	}
	
//	public static int getCost(Statement stmt) {
//		int cost = 0;
//	}
}
