/** Завдання 1: конвеєрна система з п'яти пристроїв (час у хвилинах). */
public class Task1Conveyor {
    static final double TIME = 10_000, SERVICE = 1, STEP = 1, BACK = 5;

    public static void main(String[] args) throws Exception {
        Sim s = new Sim(Nets.CreateNetConveyor(0.25))
                .track("надходження", "конвеєр 1-2", "конвеєр 2-3", "конвеєр 3-4", "конвеєр 4-5",
                        "повернення до 1")
                .run(TIME);
        int came = s.fired("надходження");
        int done = s.mark("оброблено");
        double busy = 0, inSystem = 0;
        System.out.printf("Конвеєр, T = %.0f хв, надходить 4 деталі/хв%n", TIME);
        System.out.println("Пристрій | завантаження");
        for (int i = 1; i <= 5; i++) {
            double load = 1 - s.mean("пристрій " + i + " вільний");
            busy += load;
            inSystem += s.busy("обробка " + i);
            System.out.printf("%8d | %12.4f%n", i, load);
        }
        int passes = 0;
        for (int i = 1; i <= 4; i++) {
            passes += s.fired("конвеєр " + i + "-" + (i + 1));
            inSystem += s.busy("конвеєр " + i + "-" + (i + 1));
        }
        int returns = s.fired("повернення до 1");
        inSystem += s.busy("повернення до 1");
        double throughput = done / TIME;
        System.out.printf("Надійшло деталей %d, оброблено %d%n", came, done);
        System.out.printf("Середня кількість зайнятих пристроїв: %.4f (λ·tобр = 4)%n", busy);
        System.out.printf("Середня кількість деталей у системі: %.4f%n", inSystem);
        System.out.printf("Середній час перебування деталі в системі: %.4f хв (формула Літтла)%n",
                inSystem / throughput);
        System.out.printf("  на деталь: %.4f переміщень між пристроями, "
                + "%.4f повернень до першого;%n", (double) passes / done, (double) returns / done);
        System.out.printf("  обробка + переміщення: %.4f хв%n",
                SERVICE + STEP * passes / done + BACK * returns / done);
    }
}
