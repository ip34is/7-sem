import java.util.List;

/** Завдання 2: модель запасів (завдання 4 практикуму 5) на основі PetriSim і її верифікація. */
public class Task2Fridges {
    static final double TIME = 20_000;

    record Result(int customers, int sold, int lost, int backlog, double stock, double between,
                  double lostShare, int orders, double orderSize) {
    }

    static Result run(int level, int reorder, double review) throws Exception {
        Sim s = new Sim(Nets.CreateNetFridges(level, reorder, review))
                .track("попит", "інший магазин", "доставка").run(TIME);
        List<Double> lostAt = s.exits("інший магазин");
        int customers = s.fired("попит"), lost = s.mark("продаж не відбувся");
        int orders = s.mark("розміщено замовлень");
        double between = (lostAt.getLast() - lostAt.getFirst()) / (lostAt.size() - 1);
        return new Result(customers, s.mark("продано"), lost, s.mark("невдоволений попит"),
                s.mean("запас"), between, (double) lost / customers, orders,
                (double) s.fired("доставка") / orders);
    }

    public static void main(String[] args) throws Exception {
        Result r = run(72, 18, 4);
        System.out.printf("Запаси холодильників, T = %.0f тижнів%n", TIME);
        System.out.printf("Покупців %d: продано %d, продаж не відбувся %d, очікують %d — "
                + "баланс %s%n", r.customers, r.sold, r.lost, r.backlog,
                r.customers == r.sold + r.lost + r.backlog ? "виконується" : "НЕ виконується");
        System.out.printf("Середня кількість холодильників у запасі: %.4f%n", r.stock);
        System.out.printf("Середній час між продажами, що не відбулися: %.4f тижня%n", r.between);
        System.out.printf("Частка втрачених продажів: %.4f; замовлень %d, середній розмір %.2f%n",
                r.lostShare, r.orders, r.orderSize);

        System.out.println("\nВерифікація: зміна параметрів стратегії управління запасами");
        System.out.println(" рівень | точка | перегляд | запас  | втрачено | між втратами "
                + "| замовлень | розмір");
        int[][] runs = {{72, 18, 4}, {90, 18, 4}, {60, 18, 4}, {72, 30, 4}, {72, 10, 4},
            {72, 18, 2}, {72, 18, 8}};
        for (int[] p : runs) {
            Result v = run(p[0], p[1], p[2]);
            System.out.printf(" %6d | %5d | %8d | %6.2f | %8.4f | %11.3f | %9d | %6.2f%n",
                    p[0], p[1], p[2], v.stock, v.lostShare, v.between, v.orders, v.orderSize);
        }
    }
}
