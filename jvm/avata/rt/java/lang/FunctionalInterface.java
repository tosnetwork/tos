/* Avata consensus-profile FunctionalInterface — JDK8u subset. */
package java.lang;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.lang.annotation.ElementType;

/**
 * Marker annotation indicating that an interface is a functional interface
 * (has exactly one abstract method).  Admitted for the Avata consensus
 * profile as an informational annotation only; no enforcement is performed
 * at run-time.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
public @interface FunctionalInterface {}
