/** Завдання 1: модель конвеєра (завдання 1 практикуму 5) на основі PetriSim і її верифікація. */
public class Task1Conveyor {
    static final double TIME = 10_000, SERVICE = 1, STEP = 1, BACK = 5;
    static final String[] MOVES = {"конвеєр 1-2", "конвеєр 2-3", "конвеєр 3-4", "конвеєр 4-5"};

    record Result(int came, int done, double[] loads, double busy, double inSystem,
                  double timeLittle, double timePaths, double passes, double returns) {
    }

    static Result run(double interval) throws Exception {
        Sim s = new Sim(Nets.CreateNetConveyor(interval))
                .track("надходження", "повернення до 1").track(MOVES).run(TIME);
        double[] loads = new double[5];
        double busy = 0, inSystem = 0;
        for (int i = 1; i <= 5; i++) {
            loads[i - 1] = 1 - s.mean("пристрій " + i + " вільний");
            busy += loads[i - 1];
            inSystem += s.busy("обробка " + i);
        }
        int passes = 0;
        for (String move : MOVES) {
            passes += s.fired(move);
            inSystem += s.busy(move);
        }
        inSystem += s.busy("повернення до 1");
        int done = s.mark("оброблено"), returns = s.fired("повернення до 1");
        double p = (double) passes / done, r = (double) returns / done;
        return new Result(s.fired("надходження"), done, loads, busy, inSystem,
                inSystem / (done / TIME), SERVICE + STEP * p + BACK * r, p, r);
    }

    public static void main(String[] args) throws Exception {
        Result r = run(0.25);
        System.out.printf("Конвеєр, T = %.0f хв, 4 деталі/хв: надійшло %d, оброблено %d%n",
                TIME, r.came, r.done);
        for (int i = 0; i < 5; i++) {
            System.out.printf("  завантаження пристрою %d: %.4f%n", i + 1, r.loads[i]);
        }
        System.out.printf("Середня кількість зайнятих пристроїв: %.4f%n", r.busy);
        System.out.printf("Середня кількість деталей у системі: %.4f%n", r.inSystem);
        System.out.printf("Середній час перебування: %.4f хв (Літтл), "
                + "%.4f хв (обробка + переміщення)%n", r.timeLittle, r.timePaths);

        System.out.println("\nВерифікація: зміна інтенсивності надходження деталей");
        System.out.println(" λ, дет/хв | зайнято пристроїв | λ·tобр | завантаження 1..5"
                + "             | переміщень | повернень | час, хв");
        for (double rate : new double[]{1, 2, 3, 4, 4.5}) {
            Result v = run(1 / rate);
            StringBuilder loads = new StringBuilder();
            for (double l : v.loads) {
                loads.append(String.format("%.3f ", l));
            }
            System.out.printf(" %9.1f | %17.4f | %6.2f | %s| %10.3f | %9.3f | %7.3f%n", rate,
                    v.busy, rate * SERVICE, loads, v.passes, v.returns, v.timeLittle);
        }
    }
}
