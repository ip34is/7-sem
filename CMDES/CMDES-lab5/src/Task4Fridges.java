import java.util.List;

/** Завдання 4: управління запасами холодильників (час у тижнях). */
public class Task4Fridges {
    static final double TIME = 20_000;

    public static void main(String[] args) throws Exception {
        Sim s = new Sim(Nets.CreateNetFridges(72, 18, 4))
                .track("попит", "інший магазин", "доставка").run(TIME);
        int customers = s.fired("попит"), sold = s.mark("продано");
        int lost = s.mark("продаж не відбувся"), backlog = s.mark("невдоволений попит");
        List<Double> moments = s.exits("інший магазин");
        double between = (moments.getLast() - moments.getFirst()) / (moments.size() - 1);
        System.out.printf("Запаси холодильників, T = %.0f тижнів%n", TIME);
        System.out.printf("Покупців %d: продано %d, продаж не відбувся %d, очікують %d%n",
                customers, sold, lost, backlog);
        System.out.printf("Середня кількість холодильників у запасі: %.4f%n", s.mean("запас"));
        System.out.printf("Середній час між продажами, що не відбулися: %.4f тижня "
                + "(T / кількість = %.4f)%n", between, TIME / lost);
        System.out.printf("Частка покупців, що пішли в інший магазин: %.4f%n",
                (double) lost / customers);
        System.out.printf("Середній невдоволений попит: %.4f%n", s.mean("невдоволений попит"));
        int orders = s.mark("розміщено замовлень");
        int skipped = s.mark("переглядів без замовлення");
        System.out.printf("Переглядів запасу %d, розміщено замовлень %d, "
                + "середній розмір замовлення %.2f%n", orders + skipped, orders,
                (double) s.fired("доставка") / orders);
        System.out.printf("Баланс покупців: %d = %d + %d + %d: %s%n", customers, sold, lost,
                backlog, customers == sold + lost + backlog ? "так" : "НІ");
    }
}
