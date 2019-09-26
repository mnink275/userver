#include <utils/strong_typedef.hpp>

#include <logging/logger_compat.hpp>

#include <string>
#include <unordered_map>

#include <boost/variant/variant.hpp>

#include <gtest/gtest.h>

namespace {

using MyString = utils::StrongTypedef<class MyStringTag, std::string>;
struct MyString2 final : utils::StrongTypedef<MyString2, std::string> {
  using StrongTypedef::StrongTypedef;
};
using MySpecialInt = utils::StrongTypedef<class MySpecialIntTag, int>;

struct EmptyStruct {
  static constexpr bool kOk = true;
};

}  // namespace

TEST(StrongTypedef, StringDefaultConstruction) {
  EXPECT_EQ("", MyString());
  EXPECT_EQ("", MyString{});
  EXPECT_EQ(MyString(), MyString{});
}

TEST(StrongTypedef, StringTransparentComparison) {
  EXPECT_EQ(MyString("Hello word"), "Hello word");

  MyString str{"word"};
  EXPECT_NE(str, "hello");
  str = {};
  EXPECT_EQ(str, "");

  // EXPECT_NE(str, MyString2{"qwe"}); // as expected: static asserts
}

TEST(StrongTypedef, String2TransparentComparison) {
  MyString2 ms("Hello word");

  EXPECT_EQ(MyString2("Hello word"), "Hello word");

  MyString2 str{"word"};
  EXPECT_NE(str, "hello");
  str = {};
  EXPECT_EQ(str, "");
}

TEST(StrongTypedef, StringStreamingAndLogging) {
  MyString str{"word"};

  std::ostringstream oss;
  oss << str;
  LOG_DEBUG() << str << oss.str();
}

TEST(StrongTypedef, StringInContainer) {
  std::unordered_map<MyString, MyString> umap = {
      {MyString{"Hello"}, MyString{"World"}},
  };
  EXPECT_EQ(umap[MyString{"Hello"}], "World");

  // Fails to compile (as expected):
  // std::unordered_map<std::string, std::string> umap2;
  // umap2[str] = str;
}

TEST(StrongTypedef, IntDefaultConstruction) {
  EXPECT_EQ(0, MySpecialInt());
  EXPECT_EQ(0, MySpecialInt{});
  EXPECT_EQ(MySpecialInt(), MySpecialInt{});
}

TEST(StrongTypedef, IntTransparentComparisons) {
  MySpecialInt i;
  ASSERT_EQ(0, i);

  ++i.GetUnderlying();
  EXPECT_EQ(i, 1);
  EXPECT_LE(i, 1);
  EXPECT_LT(i, 2);
  EXPECT_GT(i, 0);

  EXPECT_EQ(UnderlyingValue(i), 1);
}

TEST(StrongTypedef, IntStreamingAndLogging) {
  MySpecialInt i;
  std::ostringstream oss;
  oss << i;
  LOG_DEBUG() << i << oss.str();
}

TEST(StrongTypedef, UnorderedMap) {
  using MyMap =
      utils::StrongTypedef<class MyMapTag,
                           std::unordered_map<std::string, std::string> >;

  MyMap map = {
      {"Once", "upon a midnight dreary"},
      {"while I pondered", "weak and weary"},
      {"Over many a quaint and curious", "volumes of forgotten lore"},
  };

  EXPECT_EQ(map["Once"], "upon a midnight dreary");
}

TEST(StrongTypedef, UnorderedMapFromStrongTypedefs) {
  using MyMap =
      utils::StrongTypedef<class MyMapTag,
                           std::unordered_map<MyString, MySpecialInt> >;

  MyMap the_rings = {
      {MyString{"Elven-kings"}, MySpecialInt{3}},
      {MyString{"Dwarf-lords"}, MySpecialInt{7}},
      {MyString{"Mortal Men"}, MySpecialInt{9}},
      {MyString{"Dark Lord"}, MySpecialInt{1}},
  };

  --the_rings[MyString{"Dark Lord"}].GetUnderlying();
  EXPECT_EQ(the_rings[MyString{"Dark Lord"}], 0);
  EXPECT_EQ(the_rings[MyString{"Elven-kings"}], 3);
}

TEST(StrongTypedef, Variant) {
  using MyVariant =
      utils::StrongTypedef<class MyvariantTag,
                           boost::variant<MySpecialInt, MyString> >;

  MyVariant v{MySpecialInt{10}};
  EXPECT_EQ(boost::get<MySpecialInt>(v.GetUnderlying()), 10);
}

TEST(StrongTypedef, EmptyStruct) {
  using MyEmptyStruct =
      utils::StrongTypedef<class MyEmptyStructTag, EmptyStruct>;

  MyEmptyStruct v;
  EXPECT_TRUE(v.GetUnderlying().kOk);
}

TEST(StrongTypedef, MyIntId) {
  using MyIntId = utils::StrongTypedef<class MyIntIdTag, int>;

  MyIntId id1{123}, id2{456};

  EXPECT_NE(id1, id2);
  EXPECT_EQ(id1, MyIntId{id1});
}

TEST(StrongTypedef, MyStringId) {
  struct MyStringId final : utils::StrongTypedef<MyStringId, std::string> {
    using StrongTypedef::StrongTypedef;
  };

  MyStringId id1{"123"}, id2{"456"};

  EXPECT_NE(id1, id2);
  EXPECT_EQ(id1, MyStringId{id1});
}

TEST(StrongTypedef, NotConvertibleImplicitly) {
  struct MyStringId final : utils::StrongTypedef<MyStringId, std::string> {
    using StrongTypedef::StrongTypedef;
  };

  EXPECT_FALSE((std::is_convertible<MyString, MyString2>::value));
  EXPECT_FALSE((std::is_convertible<MyString2, MyString>::value));
  EXPECT_FALSE((std::is_convertible<MySpecialInt, MyString>::value));
  EXPECT_FALSE((std::is_convertible<MyString, MySpecialInt>::value));
  EXPECT_FALSE((std::is_convertible<MyString, int>::value));

  EXPECT_FALSE((std::is_convertible<MyString, std::string>::value));
  EXPECT_FALSE((std::is_convertible<MyString2, std::string>::value));
  EXPECT_FALSE((std::is_convertible<MySpecialInt, int>::value));
  EXPECT_FALSE((std::is_convertible<MyStringId, std::string>::value));
}

TEST(StrongTypedef, NotAssignableImplicitly) {
  struct MyStringId final : utils::StrongTypedef<MyStringId, std::string> {
    using StrongTypedef::StrongTypedef;
  };

  EXPECT_FALSE((std::is_assignable<MyString, MyString2>::value));
  EXPECT_FALSE((std::is_assignable<MyString2, MyString>::value));
  EXPECT_FALSE((std::is_assignable<MySpecialInt, MyString>::value));
  EXPECT_FALSE((std::is_assignable<MyString, MySpecialInt>::value));
  EXPECT_FALSE((std::is_assignable<MyString, int>::value));

  EXPECT_FALSE((std::is_assignable<MyString, std::string>::value));
  EXPECT_FALSE((std::is_assignable<MyString2, std::string>::value));
  EXPECT_FALSE((std::is_assignable<MySpecialInt, int>::value));
  EXPECT_FALSE((std::is_assignable<MyStringId, std::string>::value));

  EXPECT_FALSE((std::is_assignable<MyString&, MyString2>::value));
  EXPECT_FALSE((std::is_assignable<MyString2&, MyString>::value));
  EXPECT_FALSE((std::is_assignable<MySpecialInt&, MyString>::value));
  EXPECT_FALSE((std::is_assignable<MyString&, MySpecialInt>::value));
  EXPECT_FALSE((std::is_assignable<MyString&, int>::value));

  EXPECT_FALSE((std::is_assignable<MyString&, std::string>::value));
  EXPECT_FALSE((std::is_assignable<MyString2&, std::string>::value));
  EXPECT_FALSE((std::is_assignable<MySpecialInt&, int>::value));
  EXPECT_FALSE((std::is_assignable<MyStringId&, std::string>::value));
}
