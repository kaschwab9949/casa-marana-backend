import { squareFetch } from "@/lib/square";

export type MenuSectionHint = "food" | "drink" | "other";
export type MenuSectionSource = "square-taxonomy" | "keyword-fallback" | "unknown";

export type NormalizedMenuItem = {
  id: string;
  name: string;
  description: string;
  price: string;
  category: string;
  tags: string[];
  sectionHint: MenuSectionHint;
  sectionSource: MenuSectionSource;
  squareCategoryName: string;
};

type CatalogObject = Record<string, unknown>;

const MAX_PAGE_COUNT = 30;
const PAGE_LIMIT = 100;

const TAXONOMY_FOOD_KEYWORDS = [
  "pizza",
  "pizzas",
  "all food",
  "panini",
  "paninis",
  "salad",
  "salads",
  "appetizer",
  "appetizers",
  "entree",
  "entrees",
  "dessert",
  "desserts",
  "sandwich",
  "sandwiches",
  "starter",
  "starters",
  "food",
  "dish",
];

const TAXONOMY_DRINK_KEYWORDS = [
  "package",
  "draft beer",
  "draft wine",
  "mixed drinks",
  "beer",
  "wine",
  "cocktail",
  "cocktails",
  "drink",
  "drinks",
  "whiskey",
  "vodka",
  "tequila",
  "mezcal",
  "gin",
  "rum",
  "brandy",
  "non alch",
  "non-alch",
  "spirits",
  "draft",
  "soda",
  "coffee",
];

const NAME_FOOD_FALLBACK_KEYWORDS = [
  "burger",
  "fries",
  "wings",
  "sandwich",
  "panini",
  "salad",
  "appetizer",
  "dessert",
  "entree",
];

const NAME_DRINK_FALLBACK_KEYWORDS = [
  "beer",
  "wine",
  "cocktail",
  "margarita",
  "martini",
  "spritz",
  "vodka",
  "whiskey",
  "tequila",
  "mezcal",
  "gin",
  "rum",
  "soda",
  "seltzer",
  "draft",
];

function trim(value: unknown): string {
  if (typeof value !== "string") return "";
  return value.trim();
}

function asCatalogObject(value: unknown): CatalogObject {
  if (typeof value !== "object" || value === null) return {};
  return value as CatalogObject;
}

function formatPrice(cents: number): string {
  const dollars = Number(cents) / 100;
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  }).format(Number.isFinite(dollars) ? dollars : 0);
}

function includesAny(haystack: string, keywords: string[]): boolean {
  return keywords.some((keyword) => haystack.includes(keyword));
}

function classifySection(
  category: string,
  name: string,
  tags: string[]
): { sectionHint: MenuSectionHint; sectionSource: MenuSectionSource } {
  const taxonomyHaystack = [category, ...tags].join(" ").toLowerCase();
  if (includesAny(taxonomyHaystack, TAXONOMY_DRINK_KEYWORDS)) {
    return { sectionHint: "drink", sectionSource: "square-taxonomy" };
  }
  if (includesAny(taxonomyHaystack, TAXONOMY_FOOD_KEYWORDS)) {
    return { sectionHint: "food", sectionSource: "square-taxonomy" };
  }

  const nameHaystack = name.toLowerCase();
  if (includesAny(nameHaystack, NAME_DRINK_FALLBACK_KEYWORDS)) {
    return { sectionHint: "drink", sectionSource: "keyword-fallback" };
  }
  if (includesAny(nameHaystack, NAME_FOOD_FALLBACK_KEYWORDS)) {
    return { sectionHint: "food", sectionSource: "keyword-fallback" };
  }

  return { sectionHint: "other", sectionSource: "unknown" };
}

function extractItemPrice(itemData: CatalogObject): string {
  const variations = Array.isArray(itemData.variations) ? itemData.variations : [];
  const cents = variations
    .map((variation) => {
      const variationData = asCatalogObject(variation);
      const itemVariationData = asCatalogObject(variationData.item_variation_data);
      const priceMoney = asCatalogObject(itemVariationData.price_money);
      return priceMoney.amount;
    })
    .filter(
      (value: unknown): value is number =>
        typeof value === "number" && Number.isFinite(value)
    )
    .map((value) => Math.max(0, Math.floor(value)));

  if (cents.length === 0) return "";
  return formatPrice(Math.min(...cents));
}

function normalizeCatalogItem(
  object: CatalogObject,
  categoryById: Map<string, string>
): NormalizedMenuItem | null {
  const id = trim(object.id);
  const itemData = asCatalogObject(object.item_data);
  const name = trim(itemData.name);
  if (!id || !name) return null;

  const categoryId = trim(itemData.category_id);
  const category = categoryById.get(categoryId) ?? "Menu";
  const description = trim(itemData.description);

  const tags: string[] = [category];
  if (Array.isArray(itemData.categories)) {
    for (const categoryRef of itemData.categories) {
      const categoryRefData = asCatalogObject(categoryRef);
      const relatedCategoryId = trim(categoryRefData.id);
      const label = categoryById.get(relatedCategoryId);
      if (label) tags.push(label);
    }
  }

  const normalizedTags = Array.from(
    new Set(
      tags
        .map((tag) => trim(tag))
        .filter((tag) => tag.length > 0)
    )
  );

  const classification = classifySection(category, name, normalizedTags);

  return {
    id,
    name,
    description,
    price: extractItemPrice(itemData),
    category,
    tags: normalizedTags,
    sectionHint: classification.sectionHint,
    sectionSource: classification.sectionSource,
    squareCategoryName: category,
  };
}

async function fetchCatalogPage(cursor?: string) {
  const query = new URLSearchParams({
    types: "ITEM,CATEGORY",
    limit: String(PAGE_LIMIT),
  });
  if (cursor) query.set("cursor", cursor);

  return squareFetch(`/v2/catalog/list?${query.toString()}`, { method: "GET" });
}

async function fetchCatalogObjects() {
  const objects: CatalogObject[] = [];
  let cursor: string | undefined;

  for (let page = 0; page < MAX_PAGE_COUNT; page += 1) {
    const result = await fetchCatalogPage(cursor);
    if (!result.ok) {
      return {
        ok: false as const,
        error: result.error,
      };
    }

    const pageObjects = Array.isArray(result.data?.objects) ? result.data.objects : [];
    objects.push(...pageObjects);

    const nextCursor = trim(result.data?.cursor);
    if (!nextCursor) break;
    cursor = nextCursor;
  }

  return {
    ok: true as const,
    objects,
  };
}

export async function fetchNormalizedSquareMenu() {
  const catalog = await fetchCatalogObjects();
  if (!catalog.ok) {
    return {
      ok: false as const,
      error: catalog.error,
    };
  }

  const categoryById = new Map<string, string>();
  const items: NormalizedMenuItem[] = [];

  for (const object of catalog.objects) {
    const type = trim(object.type).toUpperCase();
    if (type === "CATEGORY") {
      const id = trim(object.id);
      const categoryData = asCatalogObject(object.category_data);
      const label = trim(categoryData.name);
      if (id && label) categoryById.set(id, label);
    }
  }

  for (const object of catalog.objects) {
    const type = trim(object.type).toUpperCase();
    if (type !== "ITEM") continue;
    const normalized = normalizeCatalogItem(object, categoryById);
    if (normalized) items.push(normalized);
  }

  const dedupedById = new Map<string, NormalizedMenuItem>();
  for (const item of items) dedupedById.set(item.id, item);

  const sortedItems = Array.from(dedupedById.values()).sort((a, b) => {
    if (a.sectionHint !== b.sectionHint) {
      return a.sectionHint.localeCompare(b.sectionHint);
    }
    if (a.category !== b.category) {
      return a.category.localeCompare(b.category);
    }
    return a.name.localeCompare(b.name);
  });

  return {
    ok: true as const,
    data: {
      source: "square",
      generatedAt: new Date().toISOString(),
      items: sortedItems,
    },
  };
}
