/*
 * This project is for learning purposes only, therefore there is no warranty it is going to work as expected without errors.
 * use it at your own risk.
 */

package DavidSantos.VirtualRouter;

/**
 *
 * @author root
 */
public interface RouterImplementation {
    public String[] getPPPoEUser();
    
    public void routerErrorReport(String error, StackTraceElement[] where);
    
    public void info(String info);
    
    
    
}
