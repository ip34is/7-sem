import ua.stetsenkoinna.petriobj.PetriNet;
import ua.stetsenkoinna.petriobj.PetriP;
import ua.stetsenkoinna.petriobj.PetriT;

/** Завдання 2: роботизована гнучка виробнича система, два способи закріплення роботів (с). */
public class Task2Robots {
    static final double TIME = 360_000; // 100 годин

    record Result(double perHour, double queue, double robots, double[] occupied,
                  double[] processing, double timeInSystem, int came, int stored) {
    }

    static Result run(boolean shared, double arrival) throws Exception {
        PetriNet net = shared ? Nets.CreateNetRobotsShared(arrival)
                : Nets.CreateNetRobotsDedicated(arrival);
        Sim s = new Sim(net).track("надходження").run(TIME);
        double robotsFree = 0, inSystem = 0;
        for (PetriP p : net.getListP()) {
            String n = p.getName();
            if (n.startsWith("робот: ") || n.endsWith(" вільний")) {
                robotsFree += p.getMean();
            }
            if (n.startsWith("деталь на") || n.startsWith("оброблено на")
                    || n.contains("з деталлю") || n.startsWith("робот біля деталі")) {
                inSystem += p.getMean(); // деталь чекає, лежить на верстаті або в руках робота
            }
        }
        for (PetriT t : net.getListT()) {
            String n = t.getName();
            if (n.startsWith("захоплення") || n.startsWith("переміщення")
                    || n.startsWith("обробка") || n.contains(" -> ")) {
                inSystem += t.getMean(); // деталь обробляється або до неї вже їде робот
            }
        }
        int stored = s.mark("склад");
        double throughput = stored / TIME;
        double[] occupied = {3 - s.mean("вільні місця верстат 1"),
            3 - s.mean("вільні місця верстат 2")};
        double[] processing = {s.busy("обробка верстат 1"), s.busy("обробка верстат 2")};
        return new Result(throughput * 3600, s.mean("деталь на пункті прибуття"), 3 - robotsFree,
                occupied, processing, inSystem / throughput, s.fired("надходження"), stored);
    }

    static void print(String title, Result r) {
        System.out.println(title);
        System.out.printf("  надійшло %d деталей, на складі %d%n", r.came, r.stored);
        System.out.printf("  пропускна здатність: %.2f деталі/год (надходить 90 деталей/год)%n",
                r.perHour);
        System.out.printf("  середня черга на пункті прибуття: %.2f; зайнятих роботів: %.3f з 3%n",
                r.queue, r.robots);
        for (int m = 0; m < 2; m++) {
            System.out.printf("  верстат %d: зайнято місць %.3f з 3, з них обробка %.3f%n",
                    m + 1, r.occupied[m], r.processing[m]);
        }
    }

    public static void main(String[] args) throws Exception {
        System.out.printf("Гнучка виробнича система, T = %.0f с (100 год)%n", TIME);
        print("Варіант 1: по одному роботу на кожному шляху", run(false, 40));
        print("Варіант 2: кожен робот на кожному шляху, їде найближчий", run(true, 40));
        System.out.println("\nПропускна здатність при різному інтервалі надходження, деталей/год:");
        System.out.println(" інтервал, с | надходить | варіант 1 | варіант 2 "
                + "| час у системі, с: варіант 1 | варіант 2");
        for (double arrival : new double[]{60, 50, 45, 40, 30, 20}) {
            Result a = run(false, arrival), b = run(true, arrival);
            System.out.printf(" %11.0f | %9.1f | %9.2f | %9.2f | %26.0f | %9.0f%n", arrival,
                    3600 / arrival, a.perHour, b.perHour, a.timeInSystem, b.timeInSystem);
        }
    }
}
